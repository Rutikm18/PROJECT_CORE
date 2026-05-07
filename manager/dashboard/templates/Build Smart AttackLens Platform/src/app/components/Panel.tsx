import { cn } from "../../lib/utils";
import { ReactNode } from "react";

interface PanelProps {
  children: ReactNode;
  className?: string;
}

interface PanelHeaderProps {
  title: string;
  meta?: ReactNode;
  action?: ReactNode;
  className?: string;
}

export function Panel({ children, className }: PanelProps) {
  return (
    <div
      className={cn(
        "bg-white border border-[--gray-200] rounded-lg shadow-card hover:shadow-elevated transition-shadow duration-200",
        className
      )}
    >
      {children}
    </div>
  );
}

export function PanelHeader({ title, meta, action, className }: PanelHeaderProps) {
  return (
    <div
      className={cn(
        "flex items-center justify-between px-4 py-3 border-b border-[--gray-200] bg-gradient-to-r from-[--gray-25] to-white",
        className
      )}
    >
      <h3 className="text-sm font-bold text-[--gray-800]">{title}</h3>
      <div className="flex items-center gap-3">
        {meta && <span className="text-xs font-medium text-[--gray-500]">{meta}</span>}
        {action}
      </div>
    </div>
  );
}

export function PanelBody({ children, className }: PanelProps) {
  return (
    <div className={cn("p-4", className)}>
      {children}
    </div>
  );
}
