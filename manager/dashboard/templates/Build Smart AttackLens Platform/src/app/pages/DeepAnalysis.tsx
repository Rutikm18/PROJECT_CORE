/**
 * Deep Analysis — Raw Telemetry Explorer
 * Clean explorer: section nav · time filter · agent select · structured tables
 */
import { useState, useEffect, useCallback, useRef } from "react";
import {
  Database, Search, RefreshCw, X, Clock, ChevronRight,
  ChevronDown, Cpu, Globe, Package, Activity, Users,
  Shield, HardDrive, Network, Terminal, FileText, Layers, Wifi,
  Zap, Box, Server, BookOpen, Binary, List,
} from "lucide-react";
import { cn } from "../../lib/utils";

const API = "/api/v1/raw";

// ── Types ─────────────────────────────────────────────────────────────────────
interface AgentInfo { agent_id: string; name: string; status: "online" | "stale" | "offline"; elapsed_s: number; }
interface PayloadRow { id: number; agent_id: string; section: string; collected_at: number; received_at: number; record_count: number; preview: string; data: unknown; }
type TimeWindow = "5m" | "1h" | "6h" | "24h" | "7d";

// ── Section config ────────────────────────────────────────────────────────────
const SM: Record<string, { label: string; icon: React.ElementType; dot: string }> = {
  processes:    { label: "Processes",    icon: Terminal,  dot: "#3b82f6" },
  packages:     { label: "Packages",     icon: Package,   dot: "#10b981" },
  connections:  { label: "Connections",  icon: Wifi,      dot: "#8b5cf6" },
  metrics:      { label: "Metrics",      icon: Activity,  dot: "#f59e0b" },
  users:        { label: "Users",        icon: Users,     dot: "#ef4444" },
  security:     { label: "Security",     icon: Shield,    dot: "#dc2626" },
  hardware:     { label: "Hardware",     icon: Cpu,       dot: "#6b7280" },
  network:      { label: "Network",      icon: Network,   dot: "#6366f1" },
  storage:      { label: "Storage",      icon: HardDrive, dot: "#6b7280" },
  sysctl:       { label: "Sysctl",       icon: Layers,    dot: "#6b7280" },
  configs:      { label: "Configs",      icon: FileText,  dot: "#d97706" },
  ports:        { label: "Ports",        icon: Activity,  dot: "#8b5cf6" },
  arp:          { label: "ARP",          icon: Network,   dot: "#6366f1" },
  mounts:       { label: "Mounts",       icon: HardDrive, dot: "#9ca3af" },
  battery:      { label: "Battery",      icon: Zap,       dot: "#22c55e" },
  tasks:        { label: "Tasks",        icon: Clock,     dot: "#d97706" },
  apps:         { label: "Apps",         icon: Box,       dot: "#8b5cf6" },
  services:     { label: "Services",     icon: Server,    dot: "#6366f1" },
  openfiles:    { label: "Open Files",   icon: FileText,  dot: "#9ca3af" },
  containers:   { label: "Containers",   icon: Layers,    dot: "#06b6d4" },
  sbom:         { label: "SBOM",         icon: BookOpen,  dot: "#10b981" },
  binaries:     { label: "Binaries",     icon: Terminal,  dot: "#6b7280" },
  agent_health: { label: "Agent Health", icon: Activity,  dot: "#22c55e" },
  launchagents: { label: "Launch Agents",icon: Terminal,  dot: "#ef4444" },
  crontabs:     { label: "Crontabs",     icon: Clock,     dot: "#d97706" },
};
const sm = (s: string) => SM[s] ?? { label: s, icon: Database, dot: "#9ca3af" };

const WINDOWS: { label: string; value: TimeWindow }[] = [
  { label: "5m", value: "5m" }, { label: "1h", value: "1h" },
  { label: "6h", value: "6h" }, { label: "24h", value: "24h" }, { label: "7d", value: "7d" },
];

// ── useFetch ──────────────────────────────────────────────────────────────────
function useFetch<T>(url: string | null) {
  const [data, setData]     = useState<T | null>(null);
  const [loading, setLoad]  = useState(false);
  const [error, setError]   = useState<string | null>(null);
  const [tick, setTick]     = useState(0);
  useEffect(() => {
    if (!url) return;
    let dead = false;
    setLoad(true);
    fetch(url)
      .then(r => r.ok ? r.json() : Promise.reject(`${r.status}`))
      .then(d  => { if (!dead) { setData(d); setLoad(false); setError(null); } })
      .catch(e => { if (!dead) { setError(String(e)); setLoad(false); } });
    return () => { dead = true; };
  }, [url, tick]);
  return { data, loading, error, refetch: () => setTick(t => t + 1) };
}

// ── Table atoms ───────────────────────────────────────────────────────────────
function Th({ children }: { children: React.ReactNode }) {
  return <th className="px-3 py-2 text-left text-[9.5px] font-bold text-gray-400 uppercase tracking-wider whitespace-nowrap">{children}</th>;
}
function Td({ v, mono, highlight }: { v: unknown; mono?: boolean; highlight?: boolean }) {
  const s = v == null ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v);
  return (
    <td className={cn("px-3 py-2 text-[11px] max-w-[200px] truncate border-b border-gray-50",
      mono ? "font-mono text-gray-500" : "text-gray-700",
      highlight && "font-semibold text-red-600"
    )} title={s}>{s || "—"}</td>
  );
}

// ── Section renderers ─────────────────────────────────────────────────────────
function Tbl({ cols, rows, render }: { cols: string[]; rows: Record<string,unknown>[]; render: (r: Record<string,unknown>) => React.ReactNode }) {
  return (
    <table className="w-full text-xs">
      <thead><tr className="border-b border-gray-100 bg-gray-50/60">{cols.map(c => <Th key={c}>{c}</Th>)}</tr></thead>
      <tbody>{rows.map((r, i) => <tr key={i} className="hover:bg-orange-50/20 transition-colors">{render(r)}</tr>)}</tbody>
    </table>
  );
}

// Reusable badge for boolean fields
function Badge({ v, yes = "Yes", no = "No" }: { v: unknown; yes?: string; no?: string }) {
  const on = v === true || v === "true" || v === 1;
  return (
    <td className="px-3 py-2 border-b border-gray-50">
      <span className={cn("px-1.5 py-0.5 rounded text-[9px] font-bold",
        on ? "bg-green-50 text-green-700" : "bg-gray-100 text-gray-500"
      )}>{on ? yes : no}</span>
    </td>
  );
}

function FlagBadge({ v }: { v: unknown }) {
  const on = v === true || v === "true" || v === 1;
  return (
    <td className="px-3 py-2 border-b border-gray-50">
      {on
        ? <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-red-50 text-red-700">Suspicious</span>
        : <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-gray-50 text-gray-400">OK</span>
      }
    </td>
  );
}

function renderSection(section: string, data: unknown) {
  const arr = Array.isArray(data) ? data as Record<string,unknown>[] : null;
  const obj = (!Array.isArray(data) && data && typeof data === "object") ? data as Record<string,unknown> : null;
  if (!data) return <Empty text="No data" />;
  if (arr && arr.length === 0) return <Empty text="Empty" />;
  if (arr) {
    if (section === "processes")
      return <Tbl cols={["PID","Name","User","CPU%","Mem%","Status"]} rows={arr} render={r => <>
        <Td v={r.pid} mono/><Td v={r.name??r.command}/><Td v={r.user??r.username}/>
        <Td v={r.cpu_pct??r.cpu_percent??r.cpu} mono/>
        <Td v={r.mem_pct??r.memory_percent??r.mem} mono/>
        <Td v={r.status}/>
      </>} />;

    if (section === "packages")
      return <Tbl cols={["Name","Version","Manager","Outdated"]} rows={arr} render={r => <>
        <Td v={r.name}/><Td v={r.version} mono/><Td v={r.manager??r.source}/>
        <td className="px-3 py-2 border-b border-gray-50">
          {r.outdated ? <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-50 text-amber-700">Outdated</span>
                      : <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-gray-50 text-gray-400">Current</span>}
        </td>
      </>} />;

    if (section === "connections")
      return <Tbl cols={["Proto","Local","Remote","State","PID","Process"]} rows={arr} render={r => <>
        <Td v={r.proto??r.type}/>
        <Td v={r.local_address??`${r.local_addr??''}:${r.local_port??''}`} mono/>
        <Td v={r.remote_address??`${r.remote_addr??''}:${r.remote_port??''}`} mono highlight={!!(r.remote_addr||r.remote_address)}/>
        <Td v={r.state??r.status}/><Td v={r.pid} mono/><Td v={r.process??r.name}/>
      </>} />;

    if (section === "users")
      return <Tbl cols={["Username","UID","Admin","Home","Last Login"]} rows={arr} render={r => <>
        <Td v={r.name??r.username}/><Td v={r.uid} mono/>
        <Badge v={r.admin} yes="Admin" no="User"/>
        <Td v={r.home??r.home_dir} mono/><Td v={r.last_login} mono/>
      </>} />;

    if (section === "storage")
      return <Tbl cols={["Device","Mount","FS","Total","Used","Free","Use%"]} rows={arr} render={r => <>
        <Td v={r.device??r.name} mono/><Td v={r.mountpoint??r.mount} mono/>
        <Td v={r.fstype??r.fs_type}/>
        <Td v={r.total_gb??r.total} mono/><Td v={r.used_gb??r.used} mono/>
        <Td v={r.free_gb??r.free??r.available} mono/><Td v={r.pct??r.percent} mono/>
      </>} />;

    if (section === "mounts")
      return <Tbl cols={["Device","Mount","FS","Options"]} rows={arr} render={r => <>
        <Td v={r.device} mono/><Td v={r.mountpoint??r.mount} mono/><Td v={r.fstype??r.fs_type}/><Td v={r.options} mono/>
      </>} />;

    if (section === "ports")
      return <Tbl cols={["Proto","Port","Bind","State","PID","Process"]} rows={arr} render={r => <>
        <Td v={r.proto}/><Td v={r.port} mono/><Td v={r.bind_addr??r.address} mono/>
        <Td v={r.state}/><Td v={r.pid} mono/><Td v={r.process??r.name}/>
      </>} />;

    if (section === "arp")
      return <Tbl cols={["IP","MAC","Interface","State"]} rows={arr} render={r => <>
        <Td v={r.ip??r.address} mono/><Td v={r.mac??r.hwaddr} mono/>
        <Td v={r.interface??r.iface}/><Td v={r.state??r.type}/>
      </>} />;

    if (section === "services")
      return <Tbl cols={["Name","Status","Enabled","PID","Type"]} rows={arr} render={r => <>
        <Td v={r.name??r.label}/>
        <td className="px-3 py-2 border-b border-gray-50">
          <span className={cn("px-1.5 py-0.5 rounded text-[9px] font-bold",
            r.status === "running" ? "bg-green-50 text-green-700"
            : r.status === "stopped" ? "bg-gray-100 text-gray-500"
            : "bg-amber-50 text-amber-700"
          )}>{String(r.status??r.state??"—")}</span>
        </td>
        <Badge v={r.enabled}/>
        <Td v={r.pid} mono/><Td v={r.type??r.kind}/>
      </>} />;

    if (section === "tasks")
      return <Tbl cols={["Name","Type","Schedule","Command","User","Enabled"]} rows={arr} render={r => <>
        <Td v={r.name}/><Td v={r.type}/><Td v={r.schedule??r.cron} mono/>
        <Td v={r.command??r.cmd} mono/><Td v={r.user??r.username}/>
        <Badge v={r.enabled}/>
      </>} />;

    if (section === "apps")
      return <Tbl cols={["Name","Version","Vendor","Signed","Notarized"]} rows={arr} render={r => <>
        <Td v={r.name}/><Td v={r.version} mono/><Td v={r.vendor??r.developer}/>
        <Badge v={r.signed} yes="Signed" no="Unsigned"/>
        <Badge v={r.notarized} yes="Notarized" no="No"/>
      </>} />;

    if (section === "binaries")
      return <Tbl cols={["Name","Path","SHA-256","Size","SUID","World-W"]} rows={arr} render={r => <>
        <Td v={r.name}/><Td v={r.path} mono/>
        <Td v={typeof r.hash_sha256==="string"?r.hash_sha256.slice(0,16)+"…":r.hash_sha256} mono/>
        <Td v={r.size_bytes} mono/>
        <Badge v={r.suid} yes="SUID" no="—"/>
        <Badge v={r.world_writable} yes="Yes" no="—"/>
      </>} />;

    if (section === "containers")
      return <Tbl cols={["Name","Image","Status","Runtime","Ports"]} rows={arr} render={r => <>
        <Td v={r.name??r.id}/><Td v={r.image} mono/>
        <td className="px-3 py-2 border-b border-gray-50">
          <span className={cn("px-1.5 py-0.5 rounded text-[9px] font-bold",
            r.status==="running"?"bg-green-50 text-green-700":"bg-gray-100 text-gray-500"
          )}>{String(r.status??"—")}</span>
        </td>
        <Td v={r.runtime}/><Td v={r.ports} mono/>
      </>} />;

    if (section === "sbom")
      return <Tbl cols={["Type","Name","Version","License","PURL"]} rows={arr} render={r => <>
        <Td v={r.type??r.kind}/><Td v={r.name}/><Td v={r.version} mono/>
        <Td v={r.license}/><Td v={r.purl} mono/>
      </>} />;

    if (section === "openfiles")
      return <Tbl cols={["PID","Process","Open FDs"]} rows={arr} render={r => <>
        <Td v={r.pid} mono/><Td v={r.process??r.name}/><Td v={r.fd_count??r.fds} mono/>
      </>} />;

    if (section === "hardware")
      return <Tbl cols={["Name","Vendor","Product","Serial","Bus"]} rows={arr} render={r => <>
        <Td v={r.name}/><Td v={r.vendor}/><Td v={r.product_id??r.product} mono/>
        <Td v={r.serial} mono/><Td v={r.bus}/>
      </>} />;

    if (section === "sysctl")
      return <Tbl cols={["Key","Value","Security"]} rows={arr} render={r => <>
        <Td v={r.key} mono/><Td v={r.value} mono/>
        <Badge v={r.security_relevant} yes="Yes" no="—"/>
      </>} />;

    if (section === "configs")
      return <Tbl cols={["File","Content","Flag"]} rows={arr} render={r => <>
        <Td v={r.path??r.key??r.file??r.name} mono/>
        <Td v={r.content??r.value} mono/>
        <FlagBadge v={r.suspicious}/>
      </>} />;

    if (section === "launchagents")
      return <Tbl cols={["Label","Enabled","Path"]} rows={arr} render={r => <>
        <Td v={r.label??r.name}/>
        <Badge v={r.enabled}/>
        <Td v={r.path??r.plist_path} mono/>
      </>} />;

    if (section === "crontabs")
      return <Tbl cols={["User","Schedule","Command"]} rows={arr} render={r => <>
        <Td v={r.user??r.username}/><Td v={r.schedule??r.cron} mono/><Td v={r.command??r.cmd} mono/>
      </>} />;

    // Generic fallback: auto-detect columns from first 6 keys
    const cols = [...new Set(arr.flatMap(r => Object.keys(r)))].slice(0, 6);
    return <Tbl cols={cols} rows={arr} render={r => <>{cols.map(c => <Td key={c} v={r[c]} mono/>)}</>} />;
  }
  if (obj) {
    // network: dict with interfaces array + wifi/dns/gateway metadata
    if (section === "network") {
      const ifaces = Array.isArray(obj.interfaces) ? obj.interfaces as Record<string,unknown>[] : [];
      return (
        <div className="divide-y divide-gray-100">
          {/* Metadata summary */}
          <div className="px-4 py-2.5 flex flex-wrap gap-4 text-[11px] bg-gray-50/50">
            {obj.default_gw   && <span><span className="text-gray-400 font-semibold">GW </span><span className="font-mono text-gray-700">{String(obj.default_gw)}</span></span>}
            {obj.wifi_ssid    && <span><span className="text-gray-400 font-semibold">SSID </span><span className="text-gray-700">{String(obj.wifi_ssid)}</span></span>}
            {obj.hostname     && <span><span className="text-gray-400 font-semibold">Host </span><span className="text-gray-700">{String(obj.hostname)}</span></span>}
            {Array.isArray(obj.dns_servers) && obj.dns_servers.length > 0 && (
              <span><span className="text-gray-400 font-semibold">DNS </span><span className="font-mono text-gray-700">{(obj.dns_servers as string[]).join(", ")}</span></span>
            )}
          </div>
          {/* Interfaces table */}
          {ifaces.length > 0 && (
            <Tbl cols={["Interface","IPv4","IPv6","MAC","MTU","Status"]} rows={ifaces} render={r => <>
              <Td v={r.name}/><Td v={r.ipv4??r.ip??r.address} mono/>
              <Td v={r.ipv6} mono/><Td v={r.mac??r.hwaddr} mono/>
              <Td v={r.mtu} mono/>
              <td className="px-3 py-2 border-b border-gray-50">
                <span className={cn("px-1.5 py-0.5 rounded text-[9px] font-bold",
                  r.status==="up"?"bg-green-50 text-green-700":"bg-gray-100 text-gray-500"
                )}>{String(r.status??"—")}</span>
              </td>
            </>} />
          )}
        </div>
      );
    }

    // Generic dict renderer (metrics, security, battery, etc.)
    return (
      <table className="w-full text-xs">
        <thead><tr className="border-b border-gray-100 bg-gray-50/60"><Th>Key</Th><Th>Value</Th></tr></thead>
        <tbody>
          {Object.entries(obj).map(([k, v]) => (
            <tr key={k} className="hover:bg-orange-50/20 transition-colors border-b border-gray-50">
              <td className="px-3 py-2 text-[11px] font-semibold text-gray-600 w-48 whitespace-nowrap">{k}</td>
              <td className="px-3 py-2 text-[11px] font-mono text-gray-700">
                {typeof v === "boolean"
                  ? <span className={cn("px-1.5 py-0.5 rounded text-[9px] font-bold", v ? "bg-green-50 text-green-700" : "bg-red-50 text-red-700")}>{v ? "Yes" : "No"}</span>
                  : v == null ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  return <pre className="text-[11px] font-mono text-gray-700 p-3 whitespace-pre-wrap break-words">{JSON.stringify(data, null, 2)}</pre>;
}

function Empty({ text }: { text: string }) {
  return <div className="py-10 text-center text-gray-400 text-[11px]">{text}</div>;
}

function Skeleton() {
  return (
    <div className="p-3 space-y-1.5">
      {Array.from({ length: 8 }).map((_, i) => (
        <div key={i} className="flex gap-3 py-2">
          <div className="w-20 h-2.5 bg-gray-100 rounded-full animate-pulse" style={{ animationDelay: `${i * 60}ms` }} />
          <div className="w-36 h-2.5 bg-gray-100 rounded-full animate-pulse" style={{ animationDelay: `${i * 60 + 30}ms` }} />
          <div className="flex-1 h-2.5 bg-gray-100 rounded-full animate-pulse" style={{ animationDelay: `${i * 60 + 60}ms` }} />
        </div>
      ))}
    </div>
  );
}

// ── Section nav item ──────────────────────────────────────────────────────────
function NavItem({ section: s, active, countUrl, onClick }: { section: string; active: boolean; countUrl: string; onClick: () => void }) {
  const { data } = useFetch<{ count: number }>(countUrl);
  const count    = data?.count ?? null;
  const m        = sm(s);
  const Icon     = m.icon;
  return (
    <button
      onClick={onClick}
      className={cn(
        "w-full flex items-center justify-between gap-2 px-3 py-2 text-left transition-all relative group",
        active ? "bg-orange-50 text-orange-700" : "text-gray-500 hover:bg-gray-50 hover:text-gray-700"
      )}
    >
      {active && <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 rounded-r-full" style={{ background: m.dot }} />}
      <div className="flex items-center gap-2 pl-1">
        <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: m.dot, opacity: active ? 1 : 0.5 }} />
        <Icon className="w-3 h-3 flex-shrink-0" style={{ color: active ? m.dot : undefined }} />
        <span className={cn("text-[11px] leading-tight", active ? "font-semibold" : "font-medium")}>{m.label}</span>
      </div>
      {count !== null && count > 0 && (
        <span className={cn("text-[9px] font-bold px-1.5 py-0.5 rounded-full tabular-nums flex-shrink-0",
          active ? "text-white" : "bg-gray-100 text-gray-500"
        )} style={active ? { background: m.dot } : {}}>
          {count > 9999 ? "9k+" : count > 999 ? `${Math.floor(count/1000)}k` : count}
        </span>
      )}
    </button>
  );
}

// ── Record row ────────────────────────────────────────────────────────────────
function RecordRow({ row, section, expanded, onToggle, agentName, agentOnline }: {
  row: PayloadRow; section: string; expanded: boolean; onToggle: () => void;
  agentName: string; agentOnline: boolean;
}) {
  const isArr  = Array.isArray(row.data);
  const len    = isArr ? (row.data as unknown[]).length : null;
  const lag    = row.received_at - row.collected_at;
  const dt     = new Date(row.collected_at * 1000);
  const time   = dt.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const date   = dt.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  const [showRaw, setShowRaw] = useState(false);

  return (
    <div className={cn("border-b border-gray-100 transition-colors", expanded && "bg-orange-50/20")}>
      <button onClick={onToggle} className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50/80 text-left transition-colors">
        <span className="text-gray-300">{expanded ? <ChevronDown className="w-3 h-3 text-orange-400" /> : <ChevronRight className="w-3 h-3" />}</span>
        <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", agentOnline ? "bg-green-400 animate-pulse" : "bg-gray-300")} />
        <span className="text-[10px] font-mono text-gray-400 flex-shrink-0 w-28 tabular-nums">{date} {time}</span>
        <span className="text-[11px] text-gray-700 font-medium w-24 truncate flex-shrink-0">{agentName}</span>
        {len !== null && (
          <span className="text-[10px] text-gray-400 tabular-nums flex-shrink-0 w-16">
            {len} <span className="text-gray-300">rows</span>
          </span>
        )}
        <span className="flex-1 text-[10px] font-mono text-gray-400 truncate">{row.preview}</span>
        {lag > 5 && (
          <span className="text-[9px] text-amber-600 bg-amber-50 border border-amber-100 px-1.5 py-0.5 rounded flex-shrink-0">
            +{lag}s
          </span>
        )}
      </button>
      {expanded && (
        <div className="border-t border-orange-100/60 bg-white">
          <div className="overflow-x-auto">{renderSection(section, row.data)}</div>
          <div className="px-4 py-2 border-t border-gray-50 flex items-center gap-2">
            <button onClick={() => setShowRaw(s => !s)}
              className="text-[10px] text-gray-400 hover:text-orange-500 font-medium flex items-center gap-1 transition-colors">
              {showRaw ? <ChevronDown className="w-3 h-3"/> : <ChevronRight className="w-3 h-3"/>}
              {showRaw ? "Hide" : "Raw"} JSON
            </button>
          </div>
          {showRaw && (
            <pre className="mx-4 mb-3 text-[10px] font-mono text-gray-600 bg-gray-950 text-green-400 rounded-xl p-3 overflow-auto max-h-56 whitespace-pre-wrap break-words border border-gray-800">
              {JSON.stringify(row.data, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default function DeepAnalysis() {
  const [agentId,    setAgentId]    = useState("");
  const [window_,    setWindow]     = useState<TimeWindow>("1h");
  const [section,    setSection]    = useState("");
  const [rawSearch,  setRawSearch]  = useState("");
  const [search,     setSearch]     = useState("");
  const [page,       setPage]       = useState(0);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const PAGE_SIZE = 100;
  const deb = useRef<ReturnType<typeof setTimeout> | null>(null);

  const { data: agents, refetch: rfAgents } = useFetch<AgentInfo[]>(`${API}/agents`);
  const { data: secResp } = useFetch<{ sections: string[] }>(
    agentId ? `${API}/sections?agent_id=${agentId}` : `${API}/sections`
  );
  const sections = secResp?.sections ?? [];

  useEffect(() => { if (sections.length && !section) setSection(sections[0]); }, [sections.join(",")]);

  const qUrl = useCallback(() => {
    const p = new URLSearchParams();
    if (agentId) p.set("agent_id", agentId);
    if (section) p.set("section",  section);
    p.set("window", window_);
    if (search) p.set("search", search);
    p.set("limit", String(PAGE_SIZE)); p.set("offset", String(page * PAGE_SIZE));
    return `${API}/query?${p}`;
  }, [agentId, section, window_, search, page]);

  const countUrl = useCallback((s: string) => {
    const p = new URLSearchParams();
    if (agentId) p.set("agent_id", agentId);
    p.set("section", s); p.set("window", window_);
    return `${API}/count?${p}`;
  }, [agentId, window_]);

  const { data: result, loading, error, refetch } = useFetch<{ rows: PayloadRow[] }>(qUrl());
  useEffect(() => { const t = setInterval(() => { refetch(); rfAgents(); }, 30_000); return () => clearInterval(t); }, [refetch, rfAgents]);

  const rows   = result?.rows ?? [];
  const online = agents?.filter(a => a.status === "online").length ?? 0;
  const total  = agents?.length ?? 0;
  const curMeta = sm(section);
  const CurIcon = curMeta.icon;

  return (
    <div className="flex flex-col gap-3" style={{ height: "calc(100vh - 100px)" }}>

      {/* ── Header bar ───────────────────────────────────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-card overflow-hidden flex-shrink-0">
        <div className="h-[3px]" style={{ background: "linear-gradient(90deg,#E8581A,#f97316,#fbbf24)" }} />
        <div className="flex items-center gap-3 px-4 py-2.5 flex-wrap">

          {/* Title */}
          <div className="flex items-center gap-2 flex-shrink-0">
            <Database className="w-4 h-4" style={{ color: "#E8581A" }} />
            <span className="text-[13px] font-bold text-gray-900">Deep Analysis</span>
          </div>

          {/* Stats chips */}
          <div className="flex items-center gap-2 text-[10px]">
            <span className="px-2 py-1 bg-green-50 border border-green-200 text-green-700 font-bold rounded-lg">
              {online}/{total} agents online
            </span>
            <span className="px-2 py-1 bg-gray-50 border border-gray-200 text-gray-600 font-semibold rounded-lg">
              {sections.length} sections
            </span>
            <span className="px-2 py-1 bg-orange-50 border border-orange-200 text-orange-700 font-semibold rounded-lg">
              {rows.length}{rows.length === PAGE_SIZE ? "+" : ""} rows
            </span>
          </div>

          <div className="w-px h-5 bg-gray-200 hidden sm:block" />

          {/* Agent selector */}
          <select value={agentId} onChange={e => { setAgentId(e.target.value); setSection(""); setPage(0); }}
            className="px-2.5 py-1.5 text-[11px] border border-gray-200 rounded-xl bg-white text-gray-700 focus:outline-none focus:ring-2 focus:ring-orange-200 min-w-[140px]">
            <option value="">All Agents</option>
            {(agents ?? []).map(a => (
              <option key={a.agent_id} value={a.agent_id}>
                {a.status === "online" ? "● " : "○ "}{a.name}
              </option>
            ))}
          </select>

          {/* Time window */}
          <div className="flex items-center border border-gray-200 rounded-xl overflow-hidden bg-white">
            {WINDOWS.map(w => (
              <button key={w.value} onClick={() => { setWindow(w.value); setPage(0); }}
                className={cn("px-2.5 py-1.5 text-[10px] font-bold transition-colors",
                  window_ === w.value ? "bg-orange-500 text-white" : "text-gray-500 hover:bg-gray-50"
                )}>{w.label}</button>
            ))}
          </div>

          {/* Search */}
          <div className="relative flex-1 min-w-[160px] max-w-[240px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-400 pointer-events-none" />
            <input type="text" placeholder="Search…" value={rawSearch}
              onChange={e => { setRawSearch(e.target.value); if (deb.current) clearTimeout(deb.current); deb.current = setTimeout(() => { setSearch(e.target.value); setPage(0); }, 300); }}
              className="w-full pl-7 pr-7 py-1.5 text-[11px] border border-gray-200 rounded-xl bg-white focus:outline-none focus:ring-2 focus:ring-orange-200 placeholder-gray-300" />
            {rawSearch && (
              <button onClick={() => { setRawSearch(""); setSearch(""); setPage(0); }} className="absolute right-2 top-1/2 -translate-y-1/2">
                <X className="w-3 h-3 text-gray-400" />
              </button>
            )}
          </div>

          <button onClick={refetch} className="ml-auto p-1.5 hover:bg-gray-50 rounded-lg transition-colors">
            <RefreshCw className={cn("w-3.5 h-3.5 text-gray-400", loading && "animate-spin")} />
          </button>
        </div>
      </div>

      {/* ── Body ─────────────────────────────────────────────────────────────── */}
      <div className="flex gap-3 flex-1 min-h-0">

        {/* ── Section nav ────────────────────────────────────────────────────── */}
        <div className="w-48 flex-shrink-0 bg-white border border-gray-200 rounded-2xl shadow-card flex flex-col overflow-hidden">
          <div className="px-3 py-2.5 border-b border-gray-100 flex-shrink-0">
            <span className="text-[9px] font-bold text-gray-400 uppercase tracking-widest">Sections</span>
          </div>
          <nav className="flex-1 overflow-y-auto py-1">
            {sections.length === 0
              ? <div className="px-3 py-6 text-[10px] text-gray-400 text-center">No data</div>
              : sections.map(s => (
                <NavItem key={s} section={s} active={section === s}
                  countUrl={countUrl(s)}
                  onClick={() => { setSection(s); setPage(0); setExpandedId(null); }} />
              ))}
          </nav>
        </div>

        {/* ── Data panel ─────────────────────────────────────────────────────── */}
        <div className="flex-1 min-w-0 bg-white border border-gray-200 rounded-2xl shadow-card flex flex-col overflow-hidden">

          {/* Panel header */}
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-gray-100 bg-gray-50/50 flex-shrink-0">
            {section ? (
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full" style={{ background: curMeta.dot }} />
                <CurIcon className="w-3.5 h-3.5 text-gray-500" />
                <span className="text-[12px] font-bold text-gray-800">{curMeta.label}</span>
                <span className="text-[10px] text-gray-400 font-mono">
                  {rows.length}{rows.length === PAGE_SIZE ? "+" : ""} rows · {window_}
                </span>
              </div>
            ) : (
              <span className="text-[11px] text-gray-400">← Select a section</span>
            )}
            {error && <span className="text-[10px] text-red-500">{error}</span>}
          </div>

          {/* Rows */}
          <div className="flex-1 overflow-y-auto">
            {loading && rows.length === 0 ? <Skeleton /> :
             rows.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full gap-2 text-gray-300">
                <Database className="w-10 h-10 opacity-30" />
                <p className="text-[11px] text-gray-400">No records — try a wider time window</p>
              </div>
            ) : (
              rows.map(row => (
                <RecordRow key={row.id} row={row} section={section}
                  expanded={expandedId === row.id}
                  onToggle={() => setExpandedId(expandedId === row.id ? null : row.id)}
                  agentName={agents?.find(a => a.agent_id === row.agent_id)?.name ?? row.agent_id}
                  agentOnline={agents?.find(a => a.agent_id === row.agent_id)?.status === "online"} />
              ))
            )}
          </div>

          {/* Footer pagination */}
          {rows.length > 0 && (
            <div className="flex items-center justify-between px-4 py-2 border-t border-gray-100 bg-gray-50/50 flex-shrink-0">
              <span className="text-[10px] text-gray-400">Page {page + 1} · {rows.length} records</span>
              <div className="flex gap-1.5">
                <button disabled={page === 0} onClick={() => { setPage(p => p-1); setExpandedId(null); }}
                  className="px-3 py-1 text-[10px] font-semibold border border-gray-200 rounded-lg bg-white text-gray-600 disabled:opacity-40 hover:bg-gray-50 transition-colors">← Prev</button>
                {rows.length === PAGE_SIZE && (
                  <button onClick={() => { setPage(p => p+1); setExpandedId(null); }}
                    className="px-3 py-1 text-[10px] font-semibold border border-gray-200 rounded-lg bg-white text-gray-600 hover:bg-gray-50 transition-colors">Next →</button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
