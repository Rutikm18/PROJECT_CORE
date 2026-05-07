import { cn } from "../../lib/utils";

type CTEMStage = "SCOPING" | "DISCOVERY" | "PRIORITIZATION" | "VALIDATION" | "MOBILIZATION";

interface CTEMChipProps {
  stage: CTEMStage;
  active?: boolean;
  className?: string;
}

export function CTEMChip({ stage, active = false, className }: CTEMChipProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-1 rounded-md text-[11px] font-semibold leading-[16px] shadow-sm transition-all",
        active
          ? "bg-gradient-to-r from-[--brand-orange-50] to-[--brand-orange-100] text-[--brand-orange-700] border border-[--brand-orange-700]/20"
          : "bg-[--gray-100] text-[--gray-600] border border-[--gray-300]",
        className
      )}
    >
      {stage}
    </span>
  );
}
