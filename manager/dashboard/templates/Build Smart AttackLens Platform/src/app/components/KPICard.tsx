import { cn } from "../../lib/utils";
import { ReactNode } from "react";

interface KPICardProps {
  label: string;
  value: string | number;
  meta?: ReactNode;
  delta?: {
    value: string;
    trend: "up" | "down" | "neutral";
  };
  valueColor?: string;
  className?: string;
}

export function KPICard({ label, value, meta, delta, valueColor = "text-[--gray-900]", className }: KPICardProps) {
  const deltaColors = {
    up: "bg-gradient-to-br from-[--green-50] to-[--green-100] text-[--green-600] border border-[--green-600]/20",
    down: "bg-gradient-to-br from-[--red-50] to-[--red-100] text-[--red-600] border border-[--red-600]/20",
    neutral: "bg-[--gray-100] text-[--gray-600]",
  };

  const deltaIcon = {
    up: "▲",
    down: "▼",
    neutral: "—",
  };

  return (
    <div className={cn(
      "bg-gradient-to-br from-white to-[--gray-25] border border-[--gray-200] rounded-lg p-4 relative shadow-card hover:shadow-elevated transition-all duration-200 hover:border-[--gray-300]",
      className
    )}>
      {delta && (
        <div className={cn(
          "absolute top-3 right-3 px-2 py-1 rounded-md text-[11px] font-semibold shadow-sm",
          deltaColors[delta.trend]
        )}>
          {delta.value} {deltaIcon[delta.trend]}
        </div>
      )}
      <div className="text-[11px] font-medium text-[--gray-500] uppercase tracking-wider mb-2">
        {label}
      </div>
      <div className={cn("text-[28px] font-bold leading-[36px] mb-1", valueColor)}>
        {value}
      </div>
      {meta && (
        <div className="text-xs text-[--gray-500] flex items-center gap-2 flex-wrap">
          {meta}
        </div>
      )}
    </div>
  );
}
