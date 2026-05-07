/**
 * Shared building blocks used across every page:
 *  PageHeader — colored accent bar + backstory + MITRE tags + KPI strip
 *  SevBadge, StatusBadge, MitreBadge — consistent inline chips
 *  FindingTable — reusable findings data table
 *  FilterBar — severity + status + search controls
 */
import { type ReactNode } from "react";
import { cn } from "../../lib/utils";

// ── Severity ──────────────────────────────────────────────────────────────────

const SEV_STYLES: Record<string, string> = {
  critical: "bg-[--red-100] text-[--red-700] border-[--red-600]/30",
  high:     "bg-[--amber-100] text-[--amber-700] border-[--amber-600]/30",
  medium:   "bg-[--blue-100] text-[--blue-700] border-[--blue-600]/30",
  low:      "bg-[--green-100] text-[--green-700] border-[--green-600]/30",
  info:     "bg-[--gray-100] text-[--gray-600] border-[--gray-300]",
};

export function SevBadge({ sev }: { sev: string }) {
  return (
    <span className={cn(
      "px-2 py-0.5 text-[10px] font-bold rounded border uppercase tracking-wide",
      SEV_STYLES[sev] ?? SEV_STYLES.info
    )}>
      {sev}
    </span>
  );
}

// ── Status ────────────────────────────────────────────────────────────────────

const STATUS_STYLES: Record<string, string> = {
  new:             "bg-[--red-50] text-[--red-600] border-[--red-600]/20",
  triaging:        "bg-[--amber-50] text-[--amber-700] border-[--amber-500]/20",
  investigating:   "bg-[--blue-50] text-[--blue-700] border-[--blue-600]/20",
  in_remediation:  "bg-[--purple-50] text-[--purple-600] border-[--purple-600]/20",
  remediated:      "bg-[--green-50] text-[--green-700] border-[--green-600]/20",
  closed:          "bg-[--gray-100] text-[--gray-500] border-[--gray-300]",
  false_positive:  "bg-[--gray-100] text-[--gray-500] border-[--gray-300]",
  accepted_risk:   "bg-[--amber-50] text-[--amber-600] border-[--amber-500]/20",
};

const STATUS_LABELS: Record<string, string> = {
  new:            "New",
  triaging:       "Triaging",
  investigating:  "Investigating",
  in_remediation: "In Remediation",
  remediated:     "Remediated",
  closed:         "Closed",
  false_positive: "False Positive",
  accepted_risk:  "Accepted Risk",
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={cn(
      "px-2 py-0.5 text-[10px] font-semibold rounded border",
      STATUS_STYLES[status] ?? STATUS_STYLES.new
    )}>
      {STATUS_LABELS[status] ?? status}
    </span>
  );
}

// ── MITRE badge ───────────────────────────────────────────────────────────────

export function MitreBadge({ id, label }: { id: string; label?: string }) {
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-[--indigo-50] text-[--indigo-600] border border-[--indigo-600]/20 rounded text-[10px] font-mono font-semibold">
      {id}{label && <span className="font-sans font-normal text-[--indigo-600]/70">· {label}</span>}
    </span>
  );
}

// ── KEV badge ─────────────────────────────────────────────────────────────────

export function KevBadge() {
  return (
    <span className="px-1.5 py-0.5 bg-[--red-100] text-[--red-700] border border-[--red-600]/30 rounded text-[10px] font-bold">
      KEV
    </span>
  );
}

// ── Score bar ─────────────────────────────────────────────────────────────────

export function ScoreBar({ score }: { score: number }) {
  const pct = Math.min(100, (score / 10) * 100);
  const color = score >= 8 ? "from-[--red-500] to-[--red-600]"
    : score >= 6 ? "from-[--amber-500] to-[--amber-600]"
    : score >= 4 ? "from-[--blue-500] to-[--blue-600]"
    : "from-[--green-500] to-[--green-600]";
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-[--gray-100] rounded-full">
        <div className={cn("h-full rounded-full bg-gradient-to-r", color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-bold text-[--gray-700] w-6">{score.toFixed(1)}</span>
    </div>
  );
}

// ── Page header with backstory ────────────────────────────────────────────────

interface KPI { label: string; value: string | number; color?: "red" | "amber" | "green" | "blue" | "gray" }

interface PageHeaderProps {
  icon: ReactNode;
  title: string;
  subtitle: string;
  backstory: string;
  accentClass: string;          // Tailwind border-left color class e.g. "border-[--red-600]"
  bgClass: string;              // e.g. "from-[--red-50]"
  tactics?: string[];           // MITRE tactic IDs
  techniqueIds?: { id: string; label: string }[];
  kpis?: KPI[];
  actions?: ReactNode;
}

const KPI_COLOR: Record<string, string> = {
  red:   "text-[--red-600]",
  amber: "text-[--amber-600]",
  green: "text-[--green-600]",
  blue:  "text-[--blue-600]",
  gray:  "text-[--gray-600]",
};

export function PageHeader({
  icon, title, subtitle, backstory,
  accentClass, bgClass,
  tactics, techniqueIds, kpis, actions,
}: PageHeaderProps) {
  return (
    <div className={cn(
      "bg-gradient-to-r to-white border border-[--gray-200] rounded-lg shadow-card mb-4 border-l-4",
      bgClass, accentClass
    )}>
      <div className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3 flex-1">
            <div className="mt-0.5 flex-shrink-0">{icon}</div>
            <div className="flex-1 min-w-0">
              <h1 className="text-base font-bold text-[--gray-900] mb-0.5">{title}</h1>
              <p className="text-xs font-medium text-[--gray-500] mb-2">{subtitle}</p>
              <p className="text-xs text-[--gray-600] leading-relaxed max-w-3xl">{backstory}</p>
              {(tactics || techniqueIds) && (
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {tactics?.map(t => (
                    <span key={t} className="px-1.5 py-0.5 bg-[--indigo-50] text-[--indigo-600] border border-[--indigo-600]/20 rounded text-[10px] font-medium">
                      {t}
                    </span>
                  ))}
                  {techniqueIds?.map(t => (
                    <MitreBadge key={t.id} id={t.id} label={t.label} />
                  ))}
                </div>
              )}
            </div>
          </div>
          {actions && <div className="flex items-center gap-2 flex-shrink-0">{actions}</div>}
        </div>

        {kpis && kpis.length > 0 && (
          <div className="flex items-center gap-6 mt-3 pt-3 border-t border-[--gray-200]/60">
            {kpis.map((k, i) => (
              <div key={i} className="flex flex-col">
                <span className={cn("text-lg font-bold leading-none", KPI_COLOR[k.color ?? "gray"])}>
                  {k.value}
                </span>
                <span className="text-[10px] text-[--gray-500] font-medium mt-0.5">{k.label}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Filter bar ────────────────────────────────────────────────────────────────

interface FilterBarProps {
  search: string;
  onSearch: (v: string) => void;
  severity: string;
  onSeverity: (v: string) => void;
  status: string;
  onStatus: (v: string) => void;
  extra?: ReactNode;
}

export function FilterBar({ search, onSearch, severity, onSeverity, status, onStatus, extra }: FilterBarProps) {
  return (
    <div className="flex items-center gap-2 mb-3 flex-wrap">
      <input
        type="text"
        placeholder="Search findings…"
        value={search}
        onChange={e => onSearch(e.target.value)}
        className="px-3 py-1.5 text-xs border border-[--gray-200] rounded-md bg-white text-[--gray-800] placeholder-[--gray-400] focus:outline-none focus:ring-1 focus:ring-[--brand-orange] w-52"
      />
      <select
        value={severity}
        onChange={e => onSeverity(e.target.value)}
        className="px-2 py-1.5 text-xs border border-[--gray-200] rounded-md bg-white text-[--gray-700] focus:outline-none focus:ring-1 focus:ring-[--brand-orange]"
      >
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <select
        value={status}
        onChange={e => onStatus(e.target.value)}
        className="px-2 py-1.5 text-xs border border-[--gray-200] rounded-md bg-white text-[--gray-700] focus:outline-none focus:ring-1 focus:ring-[--brand-orange]"
      >
        <option value="">All Statuses</option>
        <option value="new">New</option>
        <option value="triaging">Triaging</option>
        <option value="investigating">Investigating</option>
        <option value="in_remediation">In Remediation</option>
      </select>
      {extra}
      <div className="ml-auto text-[10px] text-[--gray-400] font-medium">Live · updates every 10s</div>
    </div>
  );
}

// ── Finding row (table row) ───────────────────────────────────────────────────

export interface Finding {
  id: number;
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  score: number;
  mitre_technique?: string;
  mitre_tactic?: string;
  agent_id: string;
  first_detected_at: number;
  last_detected_at: number;
  status: string;
  assignee?: string;
  description: string;
  cve_ids?: string;
  epss_score?: number;
  kev?: boolean;
}

export function ts(unix: number): string {
  const d = new Date(unix * 1000);
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

interface FindingRowProps {
  finding: Finding;
  onSelect?: (f: Finding) => void;
  selected?: boolean;
  showCategory?: boolean;
  showAgent?: boolean;
}

export function FindingRow({ finding: f, onSelect, selected, showCategory, showAgent }: FindingRowProps) {
  return (
    <tr
      onClick={() => onSelect?.(f)}
      className={cn(
        "border-b border-[--gray-100] hover:bg-[--gray-25] transition-colors cursor-pointer text-xs",
        selected && "bg-[--brand-orange-50] border-[--brand-orange-200]"
      )}
    >
      <td className="px-3 py-2.5">
        <div className="flex items-start gap-2">
          <SevBadge sev={f.severity} />
          <div>
            <div className="font-medium text-[--gray-800] leading-snug">{f.title}</div>
            <div className="text-[--gray-500] text-[10px] mt-0.5 line-clamp-1">{f.description}</div>
          </div>
        </div>
      </td>
      {showCategory && (
        <td className="px-3 py-2.5 text-[--gray-500] font-mono text-[10px]">{f.category}</td>
      )}
      {showAgent && (
        <td className="px-3 py-2.5 text-[--gray-600] font-medium">{f.agent_id}</td>
      )}
      <td className="px-3 py-2.5">
        <ScoreBar score={f.score} />
      </td>
      <td className="px-3 py-2.5">
        {f.mitre_technique && <MitreBadge id={f.mitre_technique} />}
      </td>
      <td className="px-3 py-2.5">
        <StatusBadge status={f.status} />
      </td>
      <td className="px-3 py-2.5 text-[--gray-500] text-[10px]">
        {f.kev && <KevBadge />}
        {f.epss_score !== undefined && (
          <span className="ml-1 font-medium text-[--amber-600]">EPSS {Math.round(f.epss_score * 100)}%</span>
        )}
      </td>
      <td className="px-3 py-2.5 text-[--gray-400] text-[10px] whitespace-nowrap">
        {ts(f.last_detected_at)}
      </td>
    </tr>
  );
}

export function FindingsTable({
  findings, onSelect, selected, showCategory, showAgent,
}: {
  findings: Finding[];
  onSelect?: (f: Finding) => void;
  selected?: Finding | null;
  showCategory?: boolean;
  showAgent?: boolean;
}) {
  return (
    <div className="bg-white border border-[--gray-200] rounded-lg shadow-card overflow-hidden">
      <table className="w-full text-xs">
        <thead>
          <tr className="bg-gradient-to-r from-[--gray-25] to-white border-b border-[--gray-200]">
            <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Finding</th>
            {showCategory && <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Category</th>}
            {showAgent && <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Agent</th>}
            <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Score</th>
            <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">MITRE</th>
            <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Status</th>
            <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Intel</th>
            <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {findings.length === 0 ? (
            <tr>
              <td colSpan={8} className="px-4 py-8 text-center text-[--gray-400] text-xs">
                No findings match the current filters
              </td>
            </tr>
          ) : (
            findings.map(f => (
              <FindingRow
                key={f.id}
                finding={f}
                onSelect={onSelect}
                selected={selected?.id === f.id}
                showCategory={showCategory}
                showAgent={showAgent}
              />
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

// ── Section heading (within page) ────────────────────────────────────────────

export function SectionHeading({ title, count, color = "gray" }: { title: string; count?: number; color?: string }) {
  const dot: Record<string, string> = {
    red: "bg-[--red-500]", amber: "bg-[--amber-500]", blue: "bg-[--blue-500]", green: "bg-[--green-500]", gray: "bg-[--gray-400]",
  };
  return (
    <div className="flex items-center gap-2 mb-2">
      <div className={cn("w-2 h-2 rounded-full", dot[color])} />
      <h2 className="text-xs font-bold text-[--gray-700] uppercase tracking-wide">{title}</h2>
      {count !== undefined && (
        <span className="px-1.5 py-0.5 bg-[--gray-100] text-[--gray-600] rounded text-[10px] font-semibold">{count}</span>
      )}
    </div>
  );
}
