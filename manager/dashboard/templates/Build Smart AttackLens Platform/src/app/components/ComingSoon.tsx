import { type ReactNode } from "react";
import { Clock } from "lucide-react";

interface ComingSoonProps {
  icon: ReactNode;
  title: string;
  description: string;
}

/** Full-page placeholder for a nav-reachable page whose feature isn't built
 * yet — keeps the page clickable (no dead/disabled nav state) while making
 * clear there's nothing live behind it yet. */
export function ComingSoon({ icon, title, description }: ComingSoonProps) {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <div className="w-14 h-14 rounded-xl bg-[--gray-100] border border-[--gray-200] flex items-center justify-center mb-4">
        {icon}
      </div>
      <h1 className="text-base font-bold text-[--gray-900] mb-1.5">{title}</h1>
      <p className="text-xs text-[--gray-500] max-w-md leading-relaxed mb-4">{description}</p>
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-[--amber-50] text-[--amber-700] border border-[--amber-600]/20 rounded-full text-[10px] font-bold uppercase tracking-wide">
        <Clock className="w-3 h-3" />
        Coming Soon
      </span>
    </div>
  );
}
