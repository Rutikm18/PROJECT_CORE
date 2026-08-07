/**
 * DeepMesh (beta) — dedicated view of the `developer_security` telemetry section.
 *
 * Coding-agent / AI-tool attack surface per endpoint. UI mirrors Deep Analysis:
 * a time-windowed list of collection records, each stamped with its collected
 * time + ingest lag, expandable to the structured capability tables. A Health
 * tab scores whether all required data is arriving accurately.
 *
 * Efficiency: the list is fetched metadata-only (include_data=false → server
 * ships preview + capability counts, not the ~300 KB payload); a row's full
 * snapshot is lazy-loaded via /raw/record?id= only when it is expanded.
 */
import { useState, useEffect, useRef, useMemo } from "react";
import {
  Radio, RefreshCw, Clock, AlertTriangle, Search, X, ShieldAlert,
  Table2, Activity, ChevronRight, ChevronDown,
} from "lucide-react";
import { cn } from "../../lib/utils";
import DevSecurityView, { DEVSEC_CAPABILITIES } from "../components/devsec/DevSecurityView";
import DeepMeshHealth from "../components/devsec/DeepMeshHealth";
import type { DevSecFilter } from "../components/devsec/devsecShared";

const API = "/api/v1/raw";

interface AgentInfo { agent_id: string; name: string; status: "online" | "stale" | "offline"; elapsed_s: number; }
interface DevSecSummary {
  counts: Record<string, number>;
  capabilities_present: number;
  partial: boolean;
  error_count: number;
  duration_ms: number | null;
}
interface ListRow {
  id: number; agent_id: string; section: string;
  collected_at: number; received_at: number;
  record_count: number; preview: string; summary: DevSecSummary | null;
}
type Tab = "overview" | "health";
type TimeWindow = "1h" | "6h" | "24h" | "7d";
const WINDOWS: TimeWindow[] = ["1h", "6h", "24h", "7d"];

function useFetch<T>(url: string | null) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoad] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const prevUrl = useRef<string | null>(null);
  useEffect(() => {
    if (!url) { setData(null); setLoad(false); setError(null); return; }
    if (prevUrl.current !== url) { setData(null); setError(null); prevUrl.current = url; }
    let dead = false;
    setLoad(true);
    fetch(url, { credentials: "include" })
      .then(r => (r.ok ? r.json() : Promise.reject(`${r.status}`)))
      .then(d => { if (!dead) { setData(d); setLoad(false); } })
      .catch(e => { if (!dead) { setError(String(e)); setLoad(false); } });
    return () => { dead = true; };
  }, [url, tick]);
  return { data, loading, error, refetch: () => setTick(t => t + 1) };
}

const COUNT_LABELS: [string, string][] = [
  ["ext", "ext"], ["mcp", "mcp"], ["browser", "browser"],
  ["cli", "cli"], ["listeners", "listen"], ["native_msg", "native"],
];

// ── One collection record (Deep-Analysis-style row, lazy-loads on expand) ─────
function RecordRow({ row, agentName, agentOnline, expanded, onToggle, filter, focus, focusNonce }: {
  row: ListRow; agentName: string; agentOnline: boolean;
  expanded: boolean; onToggle: () => void; filter: DevSecFilter;
  focus?: string; focusNonce?: number;
}) {
  const { data: full, loading } = useFetch<{ data: unknown }>(
    expanded ? `${API}/record?id=${row.id}` : null,
  );
  const [showRaw, setShowRaw] = useState(false);

  const lag = row.received_at - row.collected_at;
  const dt = new Date(row.collected_at * 1000);
  const time = dt.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const date = dt.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  const counts = row.summary?.counts ?? {};

  return (
    <div className={cn("border-b border-gray-100 transition-colors", expanded && "bg-violet-50/20")}>
      <button onClick={onToggle} className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50/80 text-left transition-colors">
        <span className="text-gray-300">{expanded ? <ChevronDown className="w-3 h-3 text-violet-400" /> : <ChevronRight className="w-3 h-3" />}</span>
        <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", agentOnline ? "bg-green-400 animate-pulse" : "bg-gray-300")} />
        <span className="text-[10px] font-mono text-gray-400 flex-shrink-0 w-28 tabular-nums">{date} {time}</span>
        <span className="text-[11px] text-gray-700 font-medium w-24 truncate flex-shrink-0">{agentName}</span>
        <span className="text-[10px] text-gray-400 tabular-nums flex-shrink-0 w-16">{row.record_count} <span className="text-gray-300">items</span></span>
        {/* Capability count chips (from server summary — no payload needed) */}
        <span className="flex-1 flex items-center gap-1.5 flex-wrap min-w-0">
          {COUNT_LABELS.filter(([k]) => (counts[k] ?? 0) > 0).map(([k, label]) => (
            <span key={k} className="text-[9px] font-semibold text-gray-500 bg-gray-100 px-1.5 py-0.5 rounded tabular-nums">
              {label} {counts[k]}
            </span>
          ))}
          {row.summary?.partial && (
            <span className="text-[9px] font-bold text-red-600 bg-red-50 border border-red-100 px-1.5 py-0.5 rounded">
              partial · {row.summary.error_count} err
            </span>
          )}
        </span>
        {lag > 5 && (
          <span className="text-[9px] text-amber-600 bg-amber-50 border border-amber-100 px-1.5 py-0.5 rounded flex-shrink-0">+{lag}s</span>
        )}
      </button>
      {expanded && (
        <div className="border-t border-violet-100/60 bg-white">
          {loading || !full ? (
            <div className="flex items-center justify-center py-10">
              <span className="w-4 h-4 border-2 border-gray-200 border-t-violet-400 rounded-full animate-spin" />
            </div>
          ) : (
            <>
              <DevSecurityView data={full.data} filter={filter} focus={focus} focusNonce={focusNonce} />
              <div className="px-4 py-2 border-t border-gray-50">
                <button onClick={() => setShowRaw(s => !s)}
                  className="text-[10px] text-gray-400 hover:text-violet-500 font-medium flex items-center gap-1 transition-colors">
                  {showRaw ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                  {showRaw ? "Hide" : "Raw"} JSON
                </button>
              </div>
              {showRaw && (
                <pre className="mx-4 mb-3 text-[10px] font-mono bg-gray-950 text-green-400 rounded-xl p-3 overflow-auto max-h-72 whitespace-pre-wrap break-words border border-gray-800">
                  {JSON.stringify(full.data, null, 2)}
                </pre>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default function DeepMesh() {
  const [agentId, setAgentId] = useState("");
  const [tab, setTab] = useState<Tab>("overview");
  const [window_, setWindow] = useState<TimeWindow>("24h");
  const [rawSearch, setRawSearch] = useState("");
  const [search, setSearch] = useState("");
  const [riskOnly, setRiskOnly] = useState(false);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [focusCap, setFocusCap] = useState<string | undefined>(undefined);
  const [focusNonce, setFocusNonce] = useState(0);
  const deb = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { data: agents, refetch: rfAgents } = useFetch<AgentInfo[]>(`${API}/agents`);

  // Metadata-only list (cheap) — the payload is lazy-loaded per row on expand.
  const listUrl = useMemo(() => {
    const p = new URLSearchParams();
    if (agentId) p.set("agent_id", agentId);
    p.set("section", "developer_security");
    p.set("window", window_);
    p.set("limit", "50");
    p.set("include_data", "false");
    return `${API}/query?${p}`;
  }, [agentId, window_]);

  const { data: result, loading, error, refetch } = useFetch<{ rows: ListRow[] }>(listUrl);

  // Health tab needs ONE full snapshot — fetched only while the tab is active.
  const healthUrl = useMemo(() => {
    if (tab !== "health") return null;
    const p = new URLSearchParams();
    if (agentId) p.set("agent_id", agentId);
    p.set("section", "developer_security");
    p.set("window", window_);
    p.set("limit", "1");
    return `${API}/query?${p}`;
  }, [tab, agentId, window_]);
  const { data: healthResult, loading: healthLoading } = useFetch<{ rows: { data: unknown; collected_at: number }[] }>(healthUrl);

  useEffect(() => { const t = setInterval(refetch, 60_000); return () => clearInterval(t); }, [refetch]);
  useEffect(() => { const t = setInterval(rfAgents, 60_000); return () => clearInterval(t); }, [rfAgents]);
  useEffect(() => () => { if (deb.current) clearTimeout(deb.current); }, []);

  const rows = result?.rows ?? [];
  const online = agents?.filter(a => a.status === "online").length ?? 0;
  const total = agents?.length ?? 0;
  const filter: DevSecFilter = { search, riskOnly };
  const nameFor = (id: string) => agents?.find(a => a.agent_id === id)?.name ?? id;
  const onlineFor = (id: string) => agents?.find(a => a.agent_id === id)?.status === "online";
  const healthRow = healthResult?.rows?.[0] ?? null;

  const TABS: { id: Tab; label: string; icon: React.ElementType }[] = [
    { id: "overview", label: "Overview", icon: Table2 },
    { id: "health",   label: "Health",   icon: Activity },
  ];

  return (
    <div className="flex flex-col gap-3" style={{ height: "calc(100vh - 100px)" }}>
      {/* Header */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-card overflow-hidden flex-shrink-0">
        <div className="h-[3px]" style={{ background: "linear-gradient(90deg,#7C3AED,#8b5cf6,#f97316)" }} />
        <div className="flex items-center gap-3 px-4 py-2.5 flex-wrap">
          <div className="flex items-center gap-2 flex-shrink-0">
            <Radio className="w-4 h-4" style={{ color: "#7C3AED" }} />
            <span className="text-[13px] font-bold text-gray-900">DeepMesh</span>
            <span className="px-1.5 py-0.5 text-[8px] font-bold uppercase tracking-wide rounded-full"
              style={{ background: "rgba(124,58,237,0.14)", color: "#7C3AED" }}>Beta</span>
          </div>

          <div className="flex items-center gap-2 text-[10px]">
            <span className="px-2 py-1 bg-green-50 border border-green-200 text-green-700 font-bold rounded-lg">
              {online}/{total} agents online
            </span>
            <span className="px-2 py-1 bg-violet-50 border border-violet-200 text-violet-700 font-semibold rounded-lg">
              {rows.length}{rows.length === 50 ? "+" : ""} snapshots
            </span>
          </div>

          <div className="w-px h-5 bg-gray-200 hidden sm:block" />

          <select value={agentId}
            onChange={e => { setAgentId(e.target.value); setExpandedId(null); }}
            className="px-2.5 py-1.5 text-[11px] border border-gray-200 rounded-xl bg-white text-gray-700 focus:outline-none focus:ring-2 focus:ring-violet-200 min-w-[160px]">
            <option value="">All agents</option>
            {(agents ?? []).map(a => (
              <option key={a.agent_id} value={a.agent_id}>{a.status === "online" ? "● " : "○ "}{a.name}</option>
            ))}
          </select>

          {/* Time window */}
          <div className="flex items-center border border-gray-200 rounded-xl overflow-hidden bg-white">
            {WINDOWS.map(w => (
              <button key={w} onClick={() => { setWindow(w); setExpandedId(null); }}
                className={cn("px-2.5 py-1.5 text-[10px] font-bold transition-colors",
                  window_ === w ? "bg-violet-500 text-white" : "text-gray-500 hover:bg-gray-50")}>{w}</button>
            ))}
          </div>

          <button onClick={refetch} className="p-1.5 hover:bg-gray-50 rounded-lg transition-colors ml-auto">
            <RefreshCw className={cn("w-3.5 h-3.5 text-gray-400", loading && "animate-spin")} />
          </button>
        </div>

        {/* Tab bar */}
        <div className="flex items-center gap-1 px-3 border-t border-gray-100">
          {TABS.map(t => {
            const Icon = t.icon;
            const active = tab === t.id;
            return (
              <button key={t.id} onClick={() => setTab(t.id)}
                className={cn("flex items-center gap-1.5 px-3 py-2 text-[11px] font-semibold border-b-2 -mb-px transition-colors",
                  active ? "border-violet-500 text-violet-700" : "border-transparent text-gray-400 hover:text-gray-600")}>
                <Icon className="w-3.5 h-3.5" /> {t.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Filter bar — Overview only */}
      {tab === "overview" && (
        <div className="bg-white border border-gray-200 rounded-2xl shadow-card px-3 py-2 flex items-center gap-2 flex-wrap flex-shrink-0">
          <div className="relative flex-1 min-w-[180px] max-w-[360px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-400 pointer-events-none" />
            <input type="text" placeholder="Filter within an expanded snapshot…"
              value={rawSearch}
              onChange={e => {
                setRawSearch(e.target.value);
                if (deb.current) clearTimeout(deb.current);
                deb.current = setTimeout(() => setSearch(e.target.value.trim()), 200);
              }}
              className="w-full pl-7 pr-7 py-1.5 text-[11px] border border-gray-200 rounded-xl bg-white focus:outline-none focus:ring-2 focus:ring-violet-200 placeholder-gray-300" />
            {rawSearch && (
              <button onClick={() => { setRawSearch(""); setSearch(""); }} className="absolute right-2 top-1/2 -translate-y-1/2">
                <X className="w-3 h-3 text-gray-400" />
              </button>
            )}
          </div>
          <button onClick={() => setRiskOnly(v => !v)}
            className={cn("inline-flex items-center gap-1.5 px-2.5 py-1.5 text-[10px] font-bold rounded-lg border transition-colors",
              riskOnly ? "bg-red-50 border-red-200 text-red-600" : "bg-white border-gray-200 text-gray-500 hover:bg-gray-50")}>
            <ShieldAlert className="w-3 h-3" /> Risk only
          </button>
        </div>
      )}

      {/* Body — Health is a single panel; Overview is nav + record list */}
      {tab === "health" ? (
        <div className="flex-1 min-h-0 bg-white border border-gray-200 rounded-2xl shadow-card overflow-hidden flex flex-col">
          {healthLoading && !healthRow ? (
            <div className="flex items-center justify-center py-20">
              <span className="w-4 h-4 border-2 border-gray-200 border-t-violet-400 rounded-full animate-spin" />
            </div>
          ) : !healthRow ? (
            <EmptyState />
          ) : (
            <div className="overflow-y-auto">
              <DeepMeshHealth data={healthRow.data} collectedAt={healthRow.collected_at} />
            </div>
          )}
        </div>
      ) : (
        <div className="flex gap-3 flex-1 min-h-0">
          {/* Capability section nav — click jumps to that capability's data */}
          <div className="w-48 flex-shrink-0 bg-white border border-gray-200 rounded-2xl shadow-card flex flex-col overflow-hidden">
            <div className="px-3 py-2.5 border-b border-gray-100 flex-shrink-0">
              <span className="text-[9px] font-bold text-gray-400 uppercase tracking-widest">Capabilities</span>
            </div>
            <nav className="flex-1 overflow-y-auto py-1">
              {DEVSEC_CAPABILITIES.map(cap => {
                const Icon = cap.icon;
                const count = rows[0]?.summary?.counts?.[cap.key];
                const active = focusCap === cap.key;
                return (
                  <button key={cap.key}
                    onClick={() => {
                      setExpandedId(prev => prev ?? rows[0]?.id ?? null);
                      setFocusCap(cap.key);
                      setFocusNonce(n => n + 1);
                    }}
                    className={cn("w-full flex items-center justify-between gap-2 px-3 py-2 text-left transition-all",
                      active ? "bg-violet-50 text-violet-700" : "text-gray-500 hover:bg-gray-50 hover:text-gray-700")}>
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: cap.dot, opacity: active ? 1 : 0.5 }} />
                      <Icon className="w-3 h-3 flex-shrink-0" style={{ color: active ? cap.dot : undefined }} />
                      <span className={cn("text-[11px] leading-tight truncate", active ? "font-semibold" : "font-medium")}>{cap.label}</span>
                    </div>
                    {count != null && count > 0 && (
                      <span className={cn("text-[9px] font-bold px-1.5 py-0.5 rounded-full tabular-nums flex-shrink-0",
                        active ? "text-white" : "bg-gray-100 text-gray-500")} style={active ? { background: cap.dot } : {}}>
                        {count > 999 ? `${Math.floor(count / 1000)}k` : count}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Record list */}
          <div className="flex-1 min-w-0 bg-white border border-gray-200 rounded-2xl shadow-card overflow-hidden flex flex-col">
            {error ? (
              <div className="flex flex-col items-center justify-center py-20 gap-2 text-gray-400">
                <AlertTriangle className="w-8 h-8 text-red-200" />
                <p className="text-[11px] text-red-500">Failed to load: {error}</p>
              </div>
            ) : loading && rows.length === 0 ? (
              <div className="flex items-center justify-center py-20">
                <span className="w-4 h-4 border-2 border-gray-200 border-t-violet-400 rounded-full animate-spin" />
              </div>
            ) : rows.length === 0 ? (
              <EmptyState window={window_} />
            ) : (
              <div className="flex-1 overflow-y-auto">
                {rows.map(row => (
                  <RecordRow key={row.id} row={row}
                    agentName={nameFor(row.agent_id)} agentOnline={onlineFor(row.agent_id)}
                    expanded={expandedId === row.id}
                    onToggle={() => { setExpandedId(expandedId === row.id ? null : row.id); setFocusCap(undefined); }}
                    filter={filter}
                    focus={expandedId === row.id ? focusCap : undefined} focusNonce={focusNonce} />
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function EmptyState({ window: w }: { window?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-2 text-gray-300">
      <Radio className="w-10 h-10 opacity-30" />
      <p className="text-[11px] text-gray-400">No developer_security telemetry{w ? ` in the last ${w}` : ""}</p>
      <p className="text-[10px] text-gray-300 flex items-center gap-1">
        <Clock className="w-3 h-3" /> collected hourly by macOS agents — check back after the next cycle
      </p>
    </div>
  );
}
