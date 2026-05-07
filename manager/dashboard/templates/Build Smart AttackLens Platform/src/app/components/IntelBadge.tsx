import { cn } from "../../lib/utils";

type IntelType = "KEV" | "EDB" | "CVSS";

interface IntelBadgeProps {
  type: IntelType;
  value?: string | number;
  className?: string;
}

const intelStyles: Record<IntelType, string> = {
  KEV: "bg-gradient-to-r from-[--brand-orange-50] to-[--brand-orange-100] text-[--brand-orange-700] border border-[--brand-orange-700]/20 shadow-sm",
  EDB: "bg-gradient-to-r from-[--blue-50] to-[--blue-100] text-[--blue-600] border border-[--blue-600]/20 shadow-sm",
  CVSS: "bg-gradient-to-r from-[--gray-100] to-[--gray-200] text-[--gray-700] border border-[--gray-400]/30",
};

export function IntelBadge({ type, value, className }: IntelBadgeProps) {
  const displayText = value ? `${type === "EDB" ? "EDB-" : ""}${value}` : type;

  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-1 rounded-md text-[11px] font-semibold leading-[16px]",
        intelStyles[type],
        className
      )}
    >
      {displayText}
    </span>
  );
}
