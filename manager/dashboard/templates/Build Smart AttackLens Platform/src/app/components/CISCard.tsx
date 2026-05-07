import { cn } from "../../lib/utils";

interface CISCardProps {
  controlId: string;
  percentage: number;
  title: string;
  failDetails: string;
}

export function CISCard({ controlId, percentage, title, failDetails }: CISCardProps) {
  const getColor = (pct: number) => {
    if (pct < 40) return { text: "text-[--red-600]", bar: "bg-gradient-to-r from-[--red-500] to-[--red-600]", border: "border-[--red-600]/20" };
    if (pct < 70) return { text: "text-[--amber-600]", bar: "bg-gradient-to-r from-[--amber-500] to-[--amber-600]", border: "border-[--amber-600]/20" };
    return { text: "text-[--green-600]", bar: "bg-gradient-to-r from-[--green-500] to-[--green-600]", border: "border-[--green-600]/20" };
  };

  const color = getColor(percentage);

  return (
    <div className={cn(
      "bg-gradient-to-br from-white to-[--gray-25] border rounded-lg p-4 shadow-sm hover:shadow-md transition-all duration-200",
      color.border
    )}>
      <div className="flex items-start justify-between mb-2">
        <div className="text-xs font-semibold text-[--gray-400]">{controlId}</div>
        <div className={cn("text-lg font-bold", color.text)}>{percentage}%</div>
      </div>
      <div className="text-[13px] font-medium text-[--gray-800] mb-3">
        {title}
      </div>
      <div className="h-1.5 bg-[--gray-100] rounded-full mb-2 shadow-inner">
        <div className={cn("h-full rounded-full shadow-sm", color.bar)} style={{ width: `${percentage}%` }}></div>
      </div>
      <div className="text-[11px] text-[--gray-500]">
        {failDetails}
      </div>
    </div>
  );
}
