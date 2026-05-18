/**
 * DeepAnalysis — Raw Telemetry Explorer
 *
 * Left panel: all sections with record counts (click to switch).
 * Right panel: structured renderer per section type + full JSON fallback.
 * Filters: agent selector · time window · free-text search.
 * Auto-refresh every 30 s.
 */
import { useState, useEffect, useCallback, useRef } from "react";
import {
  Database, Search, RefreshCw, X, Clock, ChevronRight,
  ChevronDown, Cpu, Globe, Package, Activity, Users,
  Shield, HardDrive, Network, Terminal, FileText, Layers,
} from "lucide-react";
import { cn } from "../../lib/utils";

const API = "/api/v1/raw";

// ── Types ─────────────────────────────────────────────────────────────────────

interface AgentInfo {
  agent_id: string;
  name: string;
  last_seen: number;
  last_ip: string;
  status: "online" | "stale" | "offline";
  elapsed_s: number;
}

interface PayloadRow {
  id: number;
  agent_id: string;
  section: string;
  collected_at: number;
  received_at: number;
  record_count: number;
  preview: string;
  data: unknown;
}

type TimeWindow = "5m" | "1h" | "6h" | "24h" | "7d";

// ── Section metadata ──────────────────────────────────────────────────────────

const SECTION_META: Record<string, { label: string; icon: React.ElementType; color: string; border: string }> = {
  processes:   { label: "Processes",       icon: Terminal,  color: "text-[--blue-600]",   border: "border-[--blue-200]"   },
  packages:    { label: "Packages",        icon: Package,   color: "text-[--green-600]",  border: "border-[--green-200]"  },
  connections: { label: "Connections",     icon: Globe,     color: "text-[--purple-600]", border: "border-[--purple-200]" },
  metrics:     { label: "System Metrics",  icon: Activity,  color: "text-[--amber-600]",  border: "border-[--amber-200]"  },
  users:       { label: "Users",           icon: Users,     color: "text-[--red-600]",    border: "border-[--red-200]"    },
  security:    { label: "Security",        icon: Shield,    color: "text-[--red-600]",    border: "border-[--red-200]"    },
  hardware:    { label: "Hardware",        icon: Cpu,       color: "text-[--gray-600]",   border: "border-[--gray-200]"   },
  network:     { label: "Network",         icon: Network,   color: "text-[--indigo-600]", border: "border-[--indigo-200]" },
  storage:     { label: "Storage",         icon: HardDrive, color: "text-[--gray-600]",   border: "border-[--gray-200]"   },
  sysctl:      { label: "Sysctl",          icon: Layers,    color: "text-[--gray-600]",   border: "border-[--gray-200]"   },
  configs:     { label: "Configs",         icon: FileText,  color: "text-[--amber-600]",  border: "border-[--amber-200]"  },
  launchagents:{ label: "Launch Agents",   icon: Terminal,  color: "text-[--red-600]",    border: "border-[--red-200]"    },
  crontabs:    { label: "Crontabs",        icon: Clock,     color: "text-[--amber-600]",  border: "border-[--amber-200]"  },
};

function sectionMeta(s: string) {
  return SECTION_META[s] ?? { label: s, icon: Database, color: "text-[--gray-500]", border: "border-[--gray-200]" };
}

const WINDOWS: { label: string; value: TimeWindow }[] = [
  { label: "5m",  value: "5m"  },
  { label: "1h",  value: "1h"  },
  { label: "6h",  value: "6h"  },
  { label: "24h", value: "24h" },
  { label: "7d",  value: "7d"  },
];

const STATUS_STYLE: Record<string, string> = {
  online:  "bg-[--green-500] animate-pulse",
  stale:   "bg-[--amber-500]",
  offline: "bg-[--gray-300]",
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function ts(unix: number) {
  return new Date(unix * 1000).toLocaleString("en-US", {
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function ago(s: number) {
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function val(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

// ── useFetch ──────────────────────────────────────────────────────────────────

function useFetch<T>(url: string | null) {
  const [data, setData]       = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [tick, setTick]       = useState(0);

  useEffect(() => {
    if (!url) return;
    let cancelled = false;
    setLoading(true);
    fetch(url)
      .then(r => r.ok ? r.json() : Promise.reject(`${r.status} ${r.statusText}`))
      .then(d  => { if (!cancelled) { setData(d); setLoading(false); setError(null); } })
      .catch(e => { if (!cancelled) { setError(String(e)); setLoading(false); } });
    return () => { cancelled = true; };
  }, [url, tick]);

  return { data, loading, error, refetch: () => setTick(t => t + 1) };
}

// ── Section-specific renderers ────────────────────────────────────────────────

function TblHead({ cols }: { cols: string[] }) {
  return (
    <thead>
      <tr className="border-b border-[--gray-100]">
        {cols.map(c => (
          <th key={c} className="px-3 py-2 text-left text-[10px] font-bold text-[--gray-400] uppercase tracking-wider whitespace-nowrap">
            {c}
          </th>
        ))}
      </tr>
    </thead>
  );
}

function Cell({ v, mono, highlight }: { v: unknown; mono?: boolean; highlight?: boolean }) {
  const s = val(v);
  return (
    <td className={cn(
      "px-3 py-2 text-[11px] max-w-[220px] truncate border-b border-[--gray-50]",
      mono ? "font-mono text-[--gray-600]" : "text-[--gray-700]",
      highlight && "font-semibold text-[--red-600]",
    )} title={s}>{s || "—"}</td>
  );
}

function ProcessesTable({ rows }: { rows: Record<string, unknown>[] }) {
  return (
    <table className="w-full text-xs">
      <TblHead cols={["PID", "Name", "User", "CPU %", "Mem %", "Status", "Path"]} />
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="hover:bg-[--gray-25] transition-colors">
            <Cell v={r.pid} mono />
            <Cell v={r.name ?? r.command} />
            <Cell v={r.user ?? r.username} />
            <Cell v={r.cpu_percent ?? r.cpu} mono />
            <Cell v={r.memory_percent ?? r.mem} mono />
            <Cell v={r.status} />
            <Cell v={r.exe ?? r.path ?? r.cmdline} mono />
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function PackagesTable({ rows }: { rows: Record<string, unknown>[] }) {
  return (
    <table className="w-full text-xs">
      <TblHead cols={["Name", "Version", "Source / Manager", "Installed"]} />
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="hover:bg-[--gray-25] transition-colors">
            <Cell v={r.name} />
            <Cell v={r.version} mono />
            <Cell v={r.source ?? r.manager ?? r.install_source} />
            <Cell v={r.installed_at ?? r.install_date} mono />
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ConnectionsTable({ rows }: { rows: Record<string, unknown>[] }) {
  return (
    <table className="w-full text-xs">
      <TblHead cols={["Proto", "Local Address", "Remote Address", "State", "PID", "Process"]} />
      <tbody>
        {rows.map((r, i) => {
          const local  = r.local_address  ?? `${r.local_addr ?? ""}:${r.local_port ?? ""}`;
          const remote = r.remote_address ?? `${r.remote_addr ?? ""}:${r.remote_port ?? ""}`;
          return (
            <tr key={i} className="hover:bg-[--gray-25] transition-colors">
              <Cell v={r.proto ?? r.type ?? r.protocol} />
              <Cell v={local} mono />
              <Cell v={remote} mono highlight={!!(remote && !String(remote).startsWith(":"))} />
              <Cell v={r.state ?? r.status} />
              <Cell v={r.pid} mono />
              <Cell v={r.process ?? r.name} />
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function UsersTable({ rows }: { rows: Record<string, unknown>[] }) {
  return (
    <table className="w-full text-xs">
      <TblHead cols={["Username", "UID", "Groups", "Home", "Shell", "Last Login"]} />
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="hover:bg-[--gray-25] transition-colors">
            <Cell v={r.username ?? r.name} />
            <Cell v={r.uid} mono />
            <Cell v={Array.isArray(r.groups) ? r.groups.join(", ") : r.groups} />
            <Cell v={r.home ?? r.home_dir} mono />
            <Cell v={r.shell} mono />
            <Cell v={r.last_login} mono />
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function KVTable({ obj }: { obj: Record<string, unknown> }) {
  return (
    <table className="w-full text-xs">
      <TblHead cols={["Key", "Value"]} />
      <tbody>
        {Object.entries(obj).map(([k, v]) => (
          <tr key={k} className="hover:bg-[--gray-25] transition-colors">
            <td className="px-3 py-2 text-[11px] font-semibold text-[--gray-600] border-b border-[--gray-50] w-52 whitespace-nowrap">{k}</td>
            <td className="px-3 py-2 text-[11px] font-mono text-[--gray-700] border-b border-[--gray-50]">
              {typeof v === "boolean"
                ? <span className={cn("px-1.5 py-0.5 rounded text-[10px] font-bold", v ? "bg-[--green-50] text-[--green-700]" : "bg-[--red-50] text-[--red-700]")}>{v ? "Yes" : "No"}</span>
                : val(v)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function NetworkTable({ rows }: { rows: Record<string, unknown>[] }) {
  return (
    <table className="w-full text-xs">
      <TblHead cols={["Interface", "IP Address", "Subnet", "MAC", "Type", "MTU"]} />
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="hover:bg-[--gray-25] transition-colors">
            <Cell v={r.interface ?? r.name} />
            <Cell v={r.ip ?? r.ipv4 ?? r.address} mono />
            <Cell v={r.subnet ?? r.netmask ?? r.prefix} mono />
            <Cell v={r.mac ?? r.hwaddr} mono />
            <Cell v={r.type ?? r.kind} />
            <Cell v={r.mtu} mono />
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function LaunchAgentsTable({ rows }: { rows: Record<string, unknown>[] }) {
  return (
    <table className="w-full text-xs">
      <TblHead cols={["Label", "Path", "Enabled", "Loaded", "Program"]} />
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="hover:bg-[--gray-25] transition-colors">
            <Cell v={r.label ?? r.name} />
            <Cell v={r.path ?? r.plist_path} mono />
            <td className="px-3 py-2 text-[11px] border-b border-[--gray-50]">
              <span className={cn("px-1.5 py-0.5 rounded text-[10px] font-bold",
                r.enabled !== false ? "bg-[--green-50] text-[--green-700]" : "bg-[--gray-100] text-[--gray-500]")}>
                {r.enabled !== false ? "Yes" : "No"}
              </span>
            </td>
            <Cell v={r.loaded} />
            <Cell v={r.program ?? r.program_arguments} mono />
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function CrontabsTable({ rows }: { rows: Record<string, unknown>[] }) {
  return (
    <table className="w-full text-xs">
      <TblHead cols={["User", "Schedule", "Command", "Source"]} />
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="hover:bg-[--gray-25] transition-colors">
            <Cell v={r.user ?? r.username} />
            <Cell v={r.schedule ?? r.cron} mono />
            <Cell v={r.command ?? r.cmd} mono />
            <Cell v={r.source ?? r.path ?? r.file} mono />
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ConfigsTable({ rows }: { rows: Record<string, unknown>[] }) {
  return (
    <table className="w-full text-xs">
      <TblHead cols={["File / Key", "Value", "Type"]} />
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="hover:bg-[--gray-25] transition-colors">
            <Cell v={r.key ?? r.file ?? r.path ?? r.name} mono />
            <Cell v={r.value} mono />
            <Cell v={r.type ?? r.kind} />
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function StorageTable({ rows }: { rows: Record<string, unknown>[] }) {
  return (
    <table className="w-full text-xs">
      <TblHead cols={["Device", "Mount", "FS Type", "Total", "Used", "Free", "Use %"]} />
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="hover:bg-[--gray-25] transition-colors">
            <Cell v={r.device ?? r.name} mono />
            <Cell v={r.mount ?? r.mountpoint} mono />
            <Cell v={r.fstype ?? r.fs_type} />
            <Cell v={r.total} mono />
            <Cell v={r.used} mono />
            <Cell v={r.free ?? r.available} mono />
            <Cell v={r.percent ?? r.use_percent} mono />
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── Smart section renderer ────────────────────────────────────────────────────

function SectionRenderer({ section, data }: { section: string; data: unknown }) {
  const arr = Array.isArray(data) ? data as Record<string, unknown>[] : null;
  const obj = (!Array.isArray(data) && data && typeof data === "object")
    ? data as Record<string, unknown>
    : null;

  if (!data) return <Empty text="No data in this record." />;

  if (arr && arr.length === 0) return <Empty text="Empty list." />;

  if (arr) {
    if (section === "processes")    return <ProcessesTable rows={arr} />;
    if (section === "packages")     return <PackagesTable rows={arr} />;
    if (section === "connections")  return <ConnectionsTable rows={arr} />;
    if (section === "users")        return <UsersTable rows={arr} />;
    if (section === "network")      return <NetworkTable rows={arr} />;
    if (section === "launchagents") return <LaunchAgentsTable rows={arr} />;
    if (section === "crontabs")     return <CrontabsTable rows={arr} />;
    if (section === "configs")      return <ConfigsTable rows={arr} />;
    if (section === "storage")      return <StorageTable rows={arr} />;
    // Generic array of objects
    const cols = [...new Set(arr.flatMap(r => Object.keys(r)))].slice(0, 8);
    return (
      <table className="w-full text-xs">
        <TblHead cols={cols} />
        <tbody>
          {arr.map((r, i) => (
            <tr key={i} className="hover:bg-[--gray-25] transition-colors">
              {cols.map(c => <Cell key={c} v={r[c]} mono />)}
            </tr>
          ))}
        </tbody>
      </table>
    );
  }

  if (obj) {
    if (section === "metrics" || section === "hardware" || section === "security" || section === "sysctl") {
      return <KVTable obj={obj} />;
    }
    return <KVTable obj={obj} />;
  }

  // Scalar / fallback
  return (
    <pre className="text-[11px] font-mono text-[--gray-700] whitespace-pre-wrap break-words p-3">
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

function Empty({ text }: { text: string }) {
  return (
    <div className="px-4 py-6 text-center text-[--gray-400] text-xs">{text}</div>
  );
}

// ── Skeleton ──────────────────────────────────────────────────────────────────

function Skeleton() {
  return (
    <div className="space-y-1 p-2">
      {Array.from({ length: 10 }).map((_, i) => (
        <div key={i} className="flex gap-3 py-2 border-b border-[--gray-50]">
          <div className="w-24 h-3 bg-[--gray-100] rounded animate-pulse" />
          <div className="w-32 h-3 bg-[--gray-100] rounded animate-pulse" />
          <div className="w-20 h-3 bg-[--gray-100] rounded animate-pulse" />
          <div className="flex-1 h-3 bg-[--gray-100] rounded animate-pulse" />
        </div>
      ))}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function DeepAnalysis() {
  const [agentId,    setAgentId]    = useState("");
  const [window_,    setWindow]     = useState<TimeWindow>("1h");
  const [section,    setSection]    = useState("");
  const [rawSearch,  setRawSearch]  = useState("");
  const [search,     setSearch]     = useState("");
  const [page,       setPage]       = useState(0);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const PAGE_SIZE = 100;

  const debounce = useRef<ReturnType<typeof setTimeout> | null>(null);
  const handleSearch = (v: string) => {
    setRawSearch(v);
    if (debounce.current) clearTimeout(debounce.current);
    debounce.current = setTimeout(() => { setSearch(v); setPage(0); }, 300);
  };

  // ── Agents & sections ──────────────────────────────────────────────────────
  const { data: agents, refetch: refetchAgents } = useFetch<AgentInfo[]>(`${API}/agents`);
  const { data: sectionsResp } = useFetch<{ sections: string[] }>(
    agentId ? `${API}/sections?agent_id=${agentId}` : `${API}/sections`
  );
  const allSections = sectionsResp?.sections ?? [];

  // Auto-select first section
  useEffect(() => {
    if (allSections.length && !section) setSection(allSections[0]);
  }, [allSections.join(",")]);

  // ── Payload rows ───────────────────────────────────────────────────────────
  const queryUrl = useCallback(() => {
    const p = new URLSearchParams();
    if (agentId) p.set("agent_id", agentId);
    if (section) p.set("section",  section);
    p.set("window", window_);
    if (search) p.set("search", search);
    p.set("limit",  String(PAGE_SIZE));
    p.set("offset", String(page * PAGE_SIZE));
    return `${API}/query?${p}`;
  }, [agentId, section, window_, search, page]);

  const { data: result, loading, error, refetch } = useFetch<{
    rows: PayloadRow[];
  }>(queryUrl());

  // ── Section counts (latest per section) ───────────────────────────────────
  const countUrl = useCallback((sec: string) => {
    const p = new URLSearchParams();
    if (agentId) p.set("agent_id", agentId);
    p.set("section", sec);
    p.set("window",  window_);
    return `${API}/count?${p}`;
  }, [agentId, window_]);

  // Auto-refresh 30s
  useEffect(() => {
    const t = setInterval(() => { refetch(); refetchAgents(); }, 30_000);
    return () => clearInterval(t);
  }, [refetch, refetchAgents]);

  const rows = result?.rows ?? [];
  const online = agents?.filter(a => a.status === "online").length ?? 0;
  const agentName = agents?.find(a => a.agent_id === agentId)?.name;

  return (
    <div className="flex flex-col h-full gap-3">

      {/* ── Top filter bar ──────────────────────────────────────────────────── */}
      <div className="bg-white border border-[--gray-200] rounded-lg px-4 py-3 flex items-center gap-3 flex-wrap shadow-sm flex-shrink-0">
        {/* Title */}
        <div className="flex items-center gap-2 mr-2">
          <Database className="w-4 h-4 text-[--brand-orange]" />
          <span className="text-sm font-bold text-[--gray-900]">Raw Telemetry</span>
          <span className="text-[10px] text-[--gray-400] font-mono">
            {online} agent{online !== 1 ? "s" : ""} online
          </span>
        </div>

        <div className="w-px h-5 bg-[--gray-200]" />

        {/* Agent */}
        <select
          value={agentId}
          onChange={e => { setAgentId(e.target.value); setSection(""); setPage(0); }}
          className="px-2.5 py-1.5 text-xs border border-[--gray-200] rounded-md bg-white text-[--gray-700] focus:outline-none focus:ring-1 focus:ring-[--brand-orange] min-w-[150px]"
        >
          <option value="">All Agents</option>
          {(agents ?? []).map(a => (
            <option key={a.agent_id} value={a.agent_id}>
              {a.status === "online" ? "● " : "○ "}{a.name}
            </option>
          ))}
        </select>

        {/* Time window */}
        <div className="flex items-center rounded-md border border-[--gray-200] overflow-hidden">
          <Clock className="w-3 h-3 text-[--gray-400] ml-2 mr-1" />
          {WINDOWS.map(w => (
            <button
              key={w.value}
              onClick={() => { setWindow(w.value); setPage(0); }}
              className={cn(
                "px-2.5 py-1.5 text-[10px] font-semibold transition-colors",
                window_ === w.value
                  ? "bg-[--brand-orange] text-white"
                  : "text-[--gray-500] hover:bg-[--gray-50]"
              )}
            >
              {w.label}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="relative flex-1 min-w-[180px] max-w-[280px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-[--gray-400]" />
          <input
            type="text"
            placeholder="Search any field…"
            value={rawSearch}
            onChange={e => handleSearch(e.target.value)}
            className="w-full pl-7 pr-7 py-1.5 text-xs border border-[--gray-200] rounded-md bg-white placeholder-[--gray-400] focus:outline-none focus:ring-1 focus:ring-[--brand-orange]"
          />
          {rawSearch && (
            <button
              onClick={() => { setRawSearch(""); setSearch(""); setPage(0); }}
              className="absolute right-2 top-1/2 -translate-y-1/2"
            >
              <X className="w-3 h-3 text-[--gray-400] hover:text-[--gray-600]" />
            </button>
          )}
        </div>

        <div className="ml-auto flex items-center gap-2">
          {loading && <span className="text-[10px] text-[--gray-400]">Loading…</span>}
          <button
            onClick={refetch}
            className="p-1.5 hover:bg-[--gray-100] rounded-md transition-colors"
            title="Refresh"
          >
            <RefreshCw className={cn("w-3.5 h-3.5 text-[--gray-500]", loading && "animate-spin")} />
          </button>
        </div>
      </div>

      {/* ── Body: section nav + data panel ─────────────────────────────────── */}
      <div className="flex gap-3 flex-1 min-h-0">

        {/* Section nav */}
        <div className="w-52 flex-shrink-0 bg-white border border-[--gray-200] rounded-lg shadow-sm overflow-y-auto">
          <div className="px-3 py-2 border-b border-[--gray-100]">
            <span className="text-[9px] font-bold text-[--gray-400] uppercase tracking-widest">
              Sections ({allSections.length})
            </span>
          </div>
          {allSections.length === 0 ? (
            <div className="px-3 py-4 text-[10px] text-[--gray-400] text-center">No sections found</div>
          ) : (
            <nav className="py-1">
              {allSections.map(s => {
                const meta   = sectionMeta(s);
                const Icon   = meta.icon;
                const active = section === s;
                return (
                  <SectionNavItem
                    key={s}
                    section={s}
                    meta={meta}
                    Icon={Icon}
                    active={active}
                    countUrl={countUrl(s)}
                    onClick={() => { setSection(s); setPage(0); setExpandedId(null); }}
                  />
                );
              })}
            </nav>
          )}
        </div>

        {/* Data panel */}
        <div className="flex-1 min-w-0 bg-white border border-[--gray-200] rounded-lg shadow-sm flex flex-col overflow-hidden">
          {/* Panel header */}
          {section ? (
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-[--gray-200] bg-[--gray-25] flex-shrink-0">
              <div className="flex items-center gap-2">
                {(() => { const m = sectionMeta(section); const Icon = m.icon; return <Icon className={cn("w-4 h-4", m.color)} />; })()}
                <span className="text-sm font-bold text-[--gray-800]">{sectionMeta(section).label}</span>
                {agentName && (
                  <span className="text-[10px] text-[--gray-400]">· {agentName}</span>
                )}
                <span className="ml-2 text-[10px] text-[--gray-500] bg-[--gray-100] px-1.5 py-0.5 rounded font-mono">
                  {rows.length}{rows.length === PAGE_SIZE ? "+" : ""} rows · {window_} window
                </span>
              </div>
              {error && (
                <span className="text-[10px] text-[--red-600]">Error: {error}</span>
              )}
            </div>
          ) : (
            <div className="px-4 py-2.5 border-b border-[--gray-200] bg-[--gray-25] flex-shrink-0">
              <span className="text-xs text-[--gray-400]">Select a section from the left panel</span>
            </div>
          )}

          {/* Records list */}
          <div className="flex-1 overflow-y-auto">
            {loading && rows.length === 0 ? (
              <Skeleton />
            ) : rows.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-48 text-[--gray-400] gap-1">
                <Database className="w-8 h-8 opacity-30" />
                <p className="text-xs">No records for this filter combination.</p>
                {search && <p className="text-[10px]">Try clearing the search or widening the time window.</p>}
              </div>
            ) : (
              <div className="divide-y divide-[--gray-100]">
                {rows.map(row => (
                  <RecordRow
                    key={row.id}
                    row={row}
                    section={section}
                    expanded={expandedId === row.id}
                    onToggle={() => setExpandedId(expandedId === row.id ? null : row.id)}
                    agentName={agents?.find(a => a.agent_id === row.agent_id)?.name ?? row.agent_id}
                    agentStatus={agents?.find(a => a.agent_id === row.agent_id)?.status ?? "offline"}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Pagination footer */}
          {rows.length > 0 && (
            <div className="flex items-center justify-between px-4 py-2 border-t border-[--gray-100] bg-[--gray-25] flex-shrink-0">
              <span className="text-[10px] text-[--gray-400]">
                Page {page + 1} · {rows.length} records displayed
              </span>
              <div className="flex items-center gap-2">
                <button
                  disabled={page === 0}
                  onClick={() => { setPage(p => p - 1); setExpandedId(null); }}
                  className="px-2.5 py-1 text-[10px] border border-[--gray-200] rounded bg-white text-[--gray-600] disabled:opacity-40 hover:bg-[--gray-50]"
                >
                  ← Prev
                </button>
                {rows.length === PAGE_SIZE && (
                  <button
                    onClick={() => { setPage(p => p + 1); setExpandedId(null); }}
                    className="px-2.5 py-1 text-[10px] border border-[--gray-200] rounded bg-white text-[--gray-600] hover:bg-[--gray-50]"
                  >
                    Next →
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Section nav item (fetches its own count) ──────────────────────────────────

function SectionNavItem({
  section, meta, Icon, active, countUrl, onClick,
}: {
  section: string;
  meta: ReturnType<typeof sectionMeta>;
  Icon: React.ElementType;
  active: boolean;
  countUrl: string;
  onClick: () => void;
}) {
  const { data } = useFetch<{ count: number }>(countUrl);
  const count = data?.count ?? null;

  return (
    <button
      onClick={onClick}
      className={cn(
        "w-full flex items-center justify-between gap-2 px-3 py-2 text-left transition-colors relative",
        active
          ? "bg-[--brand-orange-50] text-[--brand-orange-700]"
          : "text-[--gray-600] hover:bg-[--gray-50]"
      )}
    >
      {active && (
        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-[--brand-orange] rounded-r-full" />
      )}
      <div className="flex items-center gap-2 pl-1">
        <Icon className={cn("w-3.5 h-3.5 flex-shrink-0", active ? "text-[--brand-orange]" : meta.color)} />
        <span className={cn("text-[11px] leading-tight", active ? "font-semibold" : "font-medium")}>
          {meta.label}
        </span>
      </div>
      {count !== null && (
        <span className={cn(
          "text-[9px] font-bold px-1.5 py-0.5 rounded-full tabular-nums flex-shrink-0",
          active ? "bg-[--brand-orange] text-white" : "bg-[--gray-100] text-[--gray-500]"
        )}>
          {count > 999 ? "999+" : count}
        </span>
      )}
    </button>
  );
}

// ── Record row (collapsible) ──────────────────────────────────────────────────

function RecordRow({
  row, section, expanded, onToggle, agentName, agentStatus,
}: {
  row: PayloadRow;
  section: string;
  expanded: boolean;
  onToggle: () => void;
  agentName: string;
  agentStatus: string;
}) {
  const isArr = Array.isArray(row.data);
  const dataLen = isArr ? (row.data as unknown[]).length : null;

  return (
    <div className={cn("transition-colors", expanded && "bg-[--brand-orange-50]/30")}>
      {/* Row header — click to expand */}
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-[--gray-25] transition-colors text-left"
      >
        <span className={cn(
          "w-3.5 h-3.5 flex-shrink-0",
          expanded ? "text-[--brand-orange]" : "text-[--gray-300]"
        )}>
          {expanded
            ? <ChevronDown className="w-3.5 h-3.5" />
            : <ChevronRight className="w-3.5 h-3.5" />}
        </span>

        {/* Agent dot */}
        <span className={cn(
          "w-2 h-2 rounded-full flex-shrink-0",
          STATUS_STYLE[agentStatus] ?? STATUS_STYLE.offline
        )} />

        {/* Timestamp */}
        <span className="text-[10px] font-mono text-[--gray-500] whitespace-nowrap w-36">
          {ts(row.collected_at)}
        </span>

        {/* Agent */}
        <span className="text-[11px] text-[--gray-700] font-medium w-28 truncate">{agentName}</span>

        {/* Record count */}
        {dataLen !== null && (
          <span className="text-[10px] font-semibold text-[--gray-500] tabular-nums w-16">
            {dataLen} {dataLen === 1 ? "record" : "records"}
          </span>
        )}

        {/* Preview */}
        <span className="flex-1 text-[10px] font-mono text-[--gray-400] truncate">{row.preview}</span>

        {/* Lag badge */}
        {row.received_at - row.collected_at > 5 && (
          <span className="text-[9px] text-[--amber-700] bg-[--amber-50] border border-[--amber-200] px-1.5 py-0.5 rounded flex-shrink-0">
            +{row.received_at - row.collected_at}s lag
          </span>
        )}
      </button>

      {/* Expanded data */}
      {expanded && (
        <div className="border-t border-[--brand-orange-100] bg-white">
          {/* Structured renderer */}
          <div className="overflow-x-auto">
            <SectionRenderer section={section} data={row.data} />
          </div>

          {/* Raw JSON toggle */}
          <RawJsonToggle data={row.data} />
        </div>
      )}
    </div>
  );
}

// ── Raw JSON toggle inside expanded row ───────────────────────────────────────

function RawJsonToggle({ data }: { data: unknown }) {
  const [show, setShow] = useState(false);
  return (
    <div className="border-t border-[--gray-100] px-4 py-2">
      <button
        onClick={() => setShow(s => !s)}
        className="text-[10px] text-[--gray-400] hover:text-[--brand-orange] font-medium flex items-center gap-1 transition-colors"
      >
        {show ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
        {show ? "Hide" : "Show"} raw JSON
      </button>
      {show && (
        <pre className="mt-2 text-[10px] font-mono text-[--gray-700] bg-[--gray-25] border border-[--gray-200] rounded p-3 overflow-auto max-h-64 whitespace-pre-wrap break-words">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  );
}
