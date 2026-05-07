import { cn } from "../../lib/utils";

export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

interface SeverityBadgeProps {
  severity: SeverityLevel;
  className?: string;
}

const severityStyles: Record<SeverityLevel, string> = {
  CRITICAL: "bg-gradient-to-r from-[--red-50] to-[--red-100] text-[--red-600] border border-[--red-600]/20 shadow-sm",
  HIGH: "bg-gradient-to-r from-[--amber-50] to-[--amber-100] text-[--amber-600] border border-[--amber-600]/20 shadow-sm",
  MEDIUM: "bg-gradient-to-r from-[--blue-50] to-[--blue-100] text-[--blue-600] border border-[--blue-600]/20 shadow-sm",
  LOW: "bg-[--gray-100] text-[--gray-600] border border-[--gray-300]",
  INFO: "bg-[--gray-100] text-[--gray-500] border border-[--gray-300]",
};

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-1 rounded-md text-[11px] font-semibold leading-[16px]",
        severityStyles[severity],
        className
      )}
    >
      {severity}
    </span>
  );
}
