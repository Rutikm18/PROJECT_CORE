import { cn } from "../../lib/utils";
import { SeverityBadge } from "./SeverityBadge";

interface DomainHealthRowProps {
  domain: string;
  score: number;
  criticalCount: number;
  highCount: number;
  sections: string[];
}

export function DomainHealthRow({ domain, score, criticalCount, highCount, sections }: DomainHealthRowProps) {
  const getBarColor = (score: number) => {
    if (score >= 9) return "bg-gradient-to-r from-[--red-500] to-[--red-600] shadow-sm";
    if (score >= 7) return "bg-gradient-to-r from-[--amber-500] to-[--amber-600] shadow-sm";
    return "bg-gradient-to-r from-[--blue-500] to-[--blue-600] shadow-sm";
  };

  const getTextColor = (score: number) => {
    if (score >= 9) return "text-[--red-600]";
    if (score >= 7) return "text-[--amber-600]";
    return "text-[--blue-600]";
  };

  const percentage = (score / 10) * 100;

  return (
    <div className="py-3 border-b border-[--gray-200] last:border-0 hover:bg-[--gray-25] transition-colors px-2 -mx-2 rounded-lg">
      <div className="flex items-center gap-4 mb-2">
        <div className="w-40 text-[13px] font-semibold text-[--gray-800]">{domain}</div>
        <div className="flex-1 h-1.5 bg-[--gray-100] rounded-full shadow-inner">
          <div
            className={cn("h-full rounded-full", getBarColor(score))}
            style={{ width: `${percentage}%` }}
          ></div>
        </div>
        <div className={cn("text-[13px] font-bold w-8", getTextColor(score))}>
          {score.toFixed(1)}
        </div>
        <div className="flex items-center gap-2">
          {criticalCount > 0 && <SeverityBadge severity="CRITICAL" />}
          {criticalCount > 0 && <span className="text-xs text-[--gray-600]">{criticalCount}</span>}
          {highCount > 0 && <SeverityBadge severity="HIGH" />}
          {highCount > 0 && <span className="text-xs text-[--gray-600]">{highCount}</span>}
        </div>
      </div>
      <div className="flex items-center gap-2 ml-40 flex-wrap">
        {sections.map((section, i) => (
          <span key={i} className="px-2 py-1 bg-gradient-to-r from-[--gray-100] to-[--gray-200] text-[--gray-600] text-[10px] rounded-md font-mono border border-[--gray-300]/50 shadow-sm">
            {section}
          </span>
        ))}
      </div>
    </div>
  );
}
