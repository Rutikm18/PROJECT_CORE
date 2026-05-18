/**
 * AssetRegistry — Real-data asset inventory + SVG topology diagram.
 *
 * Data from /api/v1/assets (enriched: metrics + battery + network merged).
 * Two views: Table view (full system info) | Topology view (IP subnet diagram).
 * Click any row / node for detail modal (full overlay).
 */
import { useState, useEffect, useCallback, useRef } from "react";
import {
  Monitor, Cpu, MemoryStick, Battery, Wifi, Server,
  RefreshCw, LayoutGrid, Network, ChevronRight, X,
  HardDrive, Activity, Users, Shield, Search, Zap,
  Globe, Hash, Clock, Info, TrendingUp, Box,
} from "lucide-react";
import { cn } from "../../lib/utils";

const API = "/api/v1/assets";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Asset {
  agent_id: string;
  hostname: string;
  os: string;
  os_version: string;
  arch: string;
  status: "online" | "stale" | "offline";
  last_seen: number;
  elapsed_s: number;
  first_seen: number;
  last_ip: string;
  ip: string;
  mac: string;
  interfaces: { name: string; ip: string; mac: string; type: string; up: boolean }[];
  asset_tier: "critical" | "important" | "standard";
  importance: number;
  owner: string;
  department: string;
  asset_group: string;
  tags: string[];
  cpu_percent: number | null;
  cpu_cores: number | null;
  cpu_cores_physical: number | null;
  cpu_freq_mhz: number | null;
  mem_percent: number | null;
  mem_used_mb: number | null;
  mem_total_mb: number | null;
  mem_available_mb: number | null;
  swap_percent: number | null;
  load_1m: number | null;
  load_5m: number | null;
  uptime_sec: number | null;
  process_count: number;
  battery_present: boolean;
  battery_pct: number | null;
  battery_charging: boolean | null;
  battery_condition: string;
  battery_cycles: number | null;
}

interface TopoNode {
  agent_id: string;
  hostname: string;
  ip: string;
  mac: string;
  subnet: string;
  status: string;
  peers: { ip: string; mac: string; hostname: string }[];
}

interface TopoData {
  nodes: TopoNode[];
  subnets: { subnet: string; count: number; nodes: string[] }[];
}

type View = "table" | "topology";
type DetailTab = "overview" | "network" | "performance" | "battery";

// ── Constants ─────────────────────────────────────────────────────────────────

const TIER_CONFIG: Record<string, { bg: string; text: string; border: string; glow: string }> = {
  critical:  { bg: "bg-red-50",    text: "text-red-700",    border: "border-red-200",    glow: "shadow-red-100" },
  important: { bg: "bg-amber-50",  text: "text-amber-700",  border: "border-amber-200",  glow: "shadow-amber-100" },
  standard:  { bg: "bg-gray-100",  text: "text-gray-600",   border: "border-gray-200",   glow: "" },
};

const STATUS_COLOR: Record<string, string> = {
  online:  "#16a34a",
  stale:   "#d97706",
  offline: "#9ca3af",
};

const STATUS_BG: Record<string, string> = {
  online:  "bg-green-50 text-green-700 border-green-200",
  stale:   "bg-amber-50 text-amber-700 border-amber-200",
  offline: "bg-gray-100 text-gray-500 border-gray-200",
};

const OS_ICON: Record<string, string> = {
  mac: "🍎", darwin: "🍎", win: "🪟", linux: "🐧",
};

function getOsIcon(os: string): string {
  const l = os.toLowerCase();
  if (l.includes("mac") || l.includes("darwin")) return "🍎";
  if (l.includes("win")) return "🪟";
  if (l.includes("linux")) return "🐧";
  return "💻";
}

// ── Utility functions ─────────────────────────────────────────────────────────

function elapsed(s: number): string {
  if (!s || s > 864000) return "never";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function uptime(s: number | null): string {
  if (!s) return "—";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function mb(v: number | null): string {
  if (v == null) return "—";
  if (v >= 1024) return `${(v / 1024).toFixed(1)} GB`;
  return `${v} MB`;
}

function pct(v: number | null): string {
  return v == null ? "—" : `${v.toFixed(1)}%`;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatusDot({ status, animate = true }: { status: string; animate?: boolean }) {
  return (
    <span className="relative inline-flex flex-shrink-0">
      <span
        className={cn("w-2 h-2 rounded-full inline-block", status === "online" && animate && "opacity-75")}
        style={{ backgroundColor: STATUS_COLOR[status] ?? "#9ca3af" }}
      />
      {status === "online" && animate && (
        <span
          className="absolute inset-0 rounded-full animate-ping"
          style={{ backgroundColor: STATUS_COLOR.online, opacity: 0.4 }}
        />
      )}
    </span>
  );
}

function TierBadge({ tier }: { tier: string }) {
  const cfg = TIER_CONFIG[tier] ?? TIER_CONFIG.standard;
  return (
    <span className={cn("px-2 py-0.5 text-[10px] font-bold rounded-full border capitalize tracking-wide", cfg.bg, cfg.text, cfg.border)}>
      {tier}
    </span>
  );
}

function MiniBar({ value, color = "#2563eb" }: { value: number | null; color?: string }) {
  const v = Math.min(100, Math.max(0, value ?? 0));
  const barColor = v >= 90 ? "#dc2626" : v >= 75 ? "#d97706" : color;
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-14 h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700 ease-out"
          style={{ width: `${v}%`, backgroundColor: barColor }}
        />
      </div>
      <span className="text-[10px] font-semibold tabular-nums" style={{ color: barColor }}>
        {value == null ? "—" : `${value.toFixed(0)}%`}
      </span>
    </div>
  );
}

function BatteryIcon({ pct: p, charging }: { pct: number | null; charging: boolean | null }) {
  if (p == null) return <span className="text-gray-300 text-[10px]">—</span>;
  const color = p > 50 ? "#16a34a" : p > 20 ? "#d97706" : "#dc2626";
  return (
    <div className="flex items-center gap-1">
      <Battery className="w-3.5 h-3.5" style={{ color }} />
      <span className="text-[10px] font-bold tabular-nums" style={{ color }}>{p.toFixed(0)}%</span>
      {charging && <span className="text-[10px] text-amber-500 animate-pulse">⚡</span>}
    </div>
  );
}

// ── Circular gauge (for modal performance section) ────────────────────────────

function CircleGauge({
  value, label, color = "#2563eb", size = 88,
}: {
  value: number | null; label: string; color?: string; size?: number;
}) {
  const r = (size - 10) / 2;
  const circ = 2 * Math.PI * r;
  const v = Math.min(100, Math.max(0, value ?? 0));
  const fill = (v / 100) * circ;
  const gaugeColor = v >= 90 ? "#dc2626" : v >= 75 ? "#d97706" : color;
  const [animFill, setAnimFill] = useState(0);

  useEffect(() => {
    const t = setTimeout(() => setAnimFill(fill), 80);
    return () => clearTimeout(t);
  }, [fill]);

  return (
    <div className="flex flex-col items-center gap-1.5">
      <svg width={size} height={size} style={{ overflow: "visible" }}>
        {/* Track */}
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#f1f5f9" strokeWidth={7} />
        {/* Progress */}
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none"
          stroke={gaugeColor} strokeWidth={7}
          strokeDasharray={`${animFill} ${circ - animFill}`}
          strokeLinecap="round"
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: "stroke-dasharray 1s cubic-bezier(0.4,0,0.2,1)" }}
        />
        {/* Center value */}
        <text x="50%" y="50%" textAnchor="middle" dominantBaseline="middle"
          fontSize={13} fontWeight={700} fill={gaugeColor} fontFamily="system-ui">
          {value == null ? "—" : `${v.toFixed(0)}%`}
        </text>
      </svg>
      <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">{label}</span>
    </div>
  );
}

// ── Asset Detail Modal (full overlay) ─────────────────────────────────────────

function AssetDetailModal({ asset, onClose }: { asset: Asset; onClose: () => void }) {
  const [tab, setTab] = useState<DetailTab>("overview");
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setVisible(true), 10);
    document.body.style.overflow = "hidden";
    return () => {
      clearTimeout(t);
      document.body.style.overflow = "";
    };
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") handleClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  function handleClose() {
    setVisible(false);
    setTimeout(onClose, 200);
  }

  const tabs: { id: DetailTab; label: string; icon: React.ReactNode }[] = [
    { id: "overview",    label: "Overview",    icon: <Info className="w-3.5 h-3.5" /> },
    { id: "network",     label: "Network",     icon: <Globe className="w-3.5 h-3.5" /> },
    { id: "performance", label: "Performance", icon: <TrendingUp className="w-3.5 h-3.5" /> },
    ...(asset.battery_present
      ? [{ id: "battery" as DetailTab, label: "Battery", icon: <Battery className="w-3.5 h-3.5" /> }]
      : []),
  ];

  const statusCfg = {
    online:  { label: "Online",  dot: "bg-green-500",  ring: "ring-green-200",  text: "text-green-700",  bg: "bg-green-50" },
    stale:   { label: "Stale",   dot: "bg-amber-500",  ring: "ring-amber-200",  text: "text-amber-700",  bg: "bg-amber-50" },
    offline: { label: "Offline", dot: "bg-gray-400",   ring: "ring-gray-200",   text: "text-gray-600",   bg: "bg-gray-100" },
  }[asset.status] ?? { label: asset.status, dot: "bg-gray-400", ring: "ring-gray-200", text: "text-gray-600", bg: "bg-gray-100" };

  return (
    <div
      className={cn(
        "fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 transition-all duration-200",
        visible ? "opacity-100" : "opacity-0"
      )}
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-md"
        onClick={handleClose}
      />

      {/* Modal card */}
      <div
        className={cn(
          "relative z-10 w-full max-w-2xl bg-white rounded-2xl shadow-2xl overflow-hidden transition-all duration-300 flex flex-col",
          visible ? "translate-y-0 scale-100" : "translate-y-6 scale-95"
        )}
        style={{ maxHeight: "90vh" }}
      >
        {/* ── Modal header ──────────────────────────────────────────────── */}
        <div className="relative bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 px-6 pt-6 pb-0 flex-shrink-0">
          {/* Subtle grid pattern overlay */}
          <div
            className="absolute inset-0 opacity-5"
            style={{
              backgroundImage: "linear-gradient(rgba(255,255,255,.15) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.15) 1px, transparent 1px)",
              backgroundSize: "20px 20px",
            }}
          />

          {/* Close button */}
          <button
            onClick={handleClose}
            className="absolute top-4 right-4 p-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-white/70 hover:text-white transition-colors z-10"
          >
            <X className="w-4 h-4" />
          </button>

          {/* Asset identity */}
          <div className="relative flex items-start gap-4 mb-5">
            {/* OS icon bubble */}
            <div className="w-14 h-14 rounded-2xl bg-white/10 backdrop-blur flex items-center justify-center text-3xl flex-shrink-0 border border-white/20">
              {getOsIcon(asset.os)}
            </div>
            <div className="flex-1 min-w-0 pt-0.5">
              <h2 className="text-xl font-bold text-white truncate">{asset.hostname}</h2>
              <p className="text-gray-400 text-xs mt-0.5 font-mono truncate">{asset.agent_id}</p>
              <div className="flex items-center gap-2 mt-2.5 flex-wrap">
                {/* Status badge */}
                <span className={cn(
                  "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold border",
                  statusCfg.bg, statusCfg.text,
                  asset.status === "online" ? "border-green-200" : asset.status === "stale" ? "border-amber-200" : "border-gray-200"
                )}>
                  <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", statusCfg.dot,
                    asset.status === "online" && "animate-pulse")} />
                  {statusCfg.label}
                </span>
                <TierBadge tier={asset.asset_tier} />
                {asset.os && (
                  <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-white/10 text-gray-300 text-[11px] font-medium border border-white/10">
                    {asset.os} {asset.arch}
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Quick stats row */}
          <div className="grid grid-cols-4 gap-px bg-white/10 rounded-t-xl overflow-hidden border border-white/10 border-b-0 -mx-0">
            {[
              { label: "CPU",     value: asset.cpu_percent != null ? `${asset.cpu_percent.toFixed(0)}%` : "—", icon: <Cpu className="w-3 h-3" /> },
              { label: "RAM",     value: asset.mem_percent != null ? `${asset.mem_percent.toFixed(0)}%` : "—", icon: <MemoryStick className="w-3 h-3" /> },
              { label: "Uptime",  value: uptime(asset.uptime_sec), icon: <Clock className="w-3 h-3" /> },
              { label: "Procs",   value: String(asset.process_count || "—"), icon: <Box className="w-3 h-3" /> },
            ].map(s => (
              <div key={s.label} className="bg-white/5 px-3 py-2.5 flex flex-col items-center gap-0.5">
                <span className="text-gray-400 flex items-center gap-1 text-[10px]">{s.icon}{s.label}</span>
                <span className="text-white font-bold text-sm tabular-nums">{s.value}</span>
              </div>
            ))}
          </div>

          {/* Tabs */}
          <div className="flex gap-0 mt-0 -mx-0 border-t border-white/10">
            {tabs.map(t => (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={cn(
                  "flex items-center gap-1.5 px-4 py-2.5 text-[11px] font-semibold transition-all relative",
                  tab === t.id
                    ? "text-white"
                    : "text-gray-500 hover:text-gray-300"
                )}
              >
                {t.icon}
                {t.label}
                {tab === t.id && (
                  <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-orange-400 rounded-full" />
                )}
              </button>
            ))}
          </div>
        </div>

        {/* ── Tab content ───────────────────────────────────────────────── */}
        <div className="overflow-y-auto flex-1 bg-gray-50">
          {/* Overview tab */}
          {tab === "overview" && (
            <div className="p-5 space-y-4">
              <InfoGrid title="Identity" icon={<Monitor className="w-4 h-4 text-gray-400" />}>
                <InfoItem label="OS" value={`${asset.os} ${asset.os_version}`} />
                <InfoItem label="Architecture" value={asset.arch || "—"} />
                <InfoItem label="Last Seen" value={elapsed(asset.elapsed_s)} />
                <InfoItem label="First Seen" value={asset.first_seen ? new Date(asset.first_seen * 1000).toLocaleDateString() : "—"} />
                {asset.owner && <InfoItem label="Owner" value={asset.owner} />}
                {asset.department && <InfoItem label="Department" value={asset.department} />}
                {asset.asset_group && <InfoItem label="Group" value={asset.asset_group} />}
              </InfoGrid>

              {asset.tags && asset.tags.length > 0 && (
                <div className="bg-white rounded-xl border border-gray-100 p-4 shadow-sm">
                  <p className="text-[10px] font-bold text-gray-400 uppercase tracking-wider mb-2.5">Tags</p>
                  <div className="flex flex-wrap gap-1.5">
                    {asset.tags.map(tag => (
                      <span key={tag} className="px-2.5 py-1 bg-gray-100 text-gray-600 text-[11px] rounded-full font-medium border border-gray-200">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Network tab */}
          {tab === "network" && (
            <div className="p-5 space-y-4">
              <InfoGrid title="Primary" icon={<Globe className="w-4 h-4 text-gray-400" />}>
                <InfoItem label="IP Address" value={asset.ip || asset.last_ip || "—"} mono />
                <InfoItem label="MAC Address" value={asset.mac || "—"} mono />
              </InfoGrid>

              {asset.interfaces.length > 0 && (
                <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
                  <div className="flex items-center gap-2 px-4 py-3 border-b border-gray-100">
                    <Wifi className="w-4 h-4 text-gray-400" />
                    <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider">Interfaces</span>
                  </div>
                  <div className="divide-y divide-gray-50">
                    {asset.interfaces.map(iface => (
                      <div key={iface.name} className="px-4 py-3 flex items-center justify-between gap-3">
                        <div className="flex items-center gap-2">
                          <div className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", iface.up ? "bg-green-500" : "bg-gray-300")} />
                          <span className="text-[11px] font-bold text-gray-700">{iface.name}</span>
                          <span className="text-[10px] text-gray-400 uppercase bg-gray-100 px-1.5 py-0.5 rounded font-medium">{iface.type}</span>
                        </div>
                        <div className="text-right">
                          <p className="text-[11px] font-mono text-gray-700">{iface.ip || "—"}</p>
                          <p className="text-[10px] font-mono text-gray-400">{iface.mac || "—"}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Performance tab */}
          {tab === "performance" && (
            <div className="p-5 space-y-4">
              {/* Gauges row */}
              <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-5">
                <p className="text-[10px] font-bold text-gray-400 uppercase tracking-wider mb-5">Live Utilization</p>
                <div className="flex justify-around">
                  <CircleGauge value={asset.cpu_percent} label="CPU" color="#2563eb" />
                  <CircleGauge value={asset.mem_percent} label="RAM" color="#7c3aed" />
                  <CircleGauge value={asset.swap_percent} label="Swap" color="#d97706" />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <InfoGrid title="CPU Details" icon={<Cpu className="w-4 h-4 text-gray-400" />}>
                  <InfoItem label="Cores (logical)" value={asset.cpu_cores != null ? String(asset.cpu_cores) : "—"} />
                  <InfoItem label="Cores (physical)" value={asset.cpu_cores_physical != null ? String(asset.cpu_cores_physical) : "—"} />
                  <InfoItem label="Frequency" value={asset.cpu_freq_mhz ? `${(asset.cpu_freq_mhz / 1000).toFixed(2)} GHz` : "—"} />
                  <InfoItem label="Load 1m / 5m" value={`${asset.load_1m?.toFixed(2) ?? "—"} / ${asset.load_5m?.toFixed(2) ?? "—"}`} />
                </InfoGrid>

                <InfoGrid title="Memory Details" icon={<MemoryStick className="w-4 h-4 text-gray-400" />}>
                  <InfoItem label="Used" value={mb(asset.mem_used_mb)} />
                  <InfoItem label="Available" value={mb(asset.mem_available_mb)} />
                  <InfoItem label="Total" value={mb(asset.mem_total_mb)} />
                </InfoGrid>
              </div>

              <InfoGrid title="System" icon={<Activity className="w-4 h-4 text-gray-400" />}>
                <InfoItem label="Uptime" value={uptime(asset.uptime_sec)} />
                <InfoItem label="Processes" value={String(asset.process_count || "—")} />
              </InfoGrid>
            </div>
          )}

          {/* Battery tab */}
          {tab === "battery" && asset.battery_present && (
            <div className="p-5 space-y-4">
              <div className="bg-white rounded-xl border border-gray-100 shadow-sm p-6">
                <div className="flex items-center gap-6">
                  <CircleGauge
                    value={asset.battery_pct}
                    label="Charge"
                    color={
                      asset.battery_pct != null && asset.battery_pct > 50 ? "#16a34a"
                      : asset.battery_pct != null && asset.battery_pct > 20 ? "#d97706"
                      : "#dc2626"
                    }
                    size={100}
                  />
                  <div className="space-y-2 flex-1">
                    <InfoItem label="Status" value={
                      asset.battery_charging
                        ? "⚡ Charging"
                        : asset.battery_pct != null && asset.battery_pct > 20
                        ? "Discharging"
                        : "⚠ Low Battery"
                    } />
                    <InfoItem label="Condition" value={asset.battery_condition || "—"} />
                    <InfoItem label="Cycle Count" value={asset.battery_cycles != null ? String(asset.battery_cycles) : "—"} />
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex-shrink-0 flex items-center justify-between px-5 py-3 bg-white border-t border-gray-100">
          <span className="text-[10px] text-gray-400 font-mono">{asset.agent_id}</span>
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-gray-400">Last seen {elapsed(asset.elapsed_s)}</span>
            <button
              onClick={handleClose}
              className="px-3 py-1.5 rounded-lg bg-gray-100 hover:bg-gray-200 text-gray-600 text-xs font-medium transition-colors"
            >
              Close  <kbd className="ml-1 text-[9px] text-gray-400 bg-gray-200 px-1 py-0.5 rounded">ESC</kbd>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── InfoGrid + InfoItem for modal ─────────────────────────────────────────────

function InfoGrid({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-gray-100">
        {icon}
        <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider">{title}</span>
      </div>
      <div className="px-4 py-3 space-y-2">{children}</div>
    </div>
  );
}

function InfoItem({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 py-0.5">
      <span className="text-[11px] text-gray-400 font-medium flex-shrink-0 pt-0.5">{label}</span>
      <span className={cn("text-[11px] text-gray-800 font-semibold text-right flex-1", mono && "font-mono")}>
        {value}
      </span>
    </div>
  );
}

// ── Section / Row for legacy use (topology detail) ────────────────────────────

function Section({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="border-b border-gray-100 last:border-b-0">
      <div className="flex items-center gap-1.5 px-3 py-2 bg-gray-50">
        <span className="text-gray-400">{icon}</span>
        <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wide">{title}</span>
      </div>
      <div className="px-3 pb-2 space-y-1.5">{children}</div>
    </div>
  );
}

function Row({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-center gap-2 py-0.5">
      <span className="w-20 text-[10px] text-gray-400 font-medium flex-shrink-0">{label}</span>
      <span className={cn("text-[11px] text-gray-700 flex-1", mono && "font-mono")}>{value}</span>
    </div>
  );
}

// ── Topology SVG ──────────────────────────────────────────────────────────────

function TopologyDiagram({
  topo, assets, onSelect, selected,
}: {
  topo: TopoData; assets: Asset[]; onSelect: (id: string) => void; selected: string | null;
}) {
  const assetMap = new Map(assets.map(a => [a.agent_id, a]));
  const W = 900;
  const NODE_R = 28;
  const SUBNET_H = 120;

  const subnets = topo.subnets;
  const totalH = subnets.length * (SUBNET_H + 40) + 60;

  const nodePositions = new Map<string, { x: number; y: number }>();
  subnets.forEach((sub, si) => {
    const y = 50 + si * (SUBNET_H + 40) + SUBNET_H / 2;
    const count = sub.nodes.length;
    const spacing = Math.min(160, (W - 120) / Math.max(count, 1));
    const startX = (W - spacing * (count - 1)) / 2;
    sub.nodes.forEach((nid, ni) => {
      nodePositions.set(nid, { x: startX + ni * spacing, y });
    });
  });

  const edges: { x1: number; y1: number; x2: number; y2: number }[] = [];
  topo.nodes.forEach(node => {
    const from = nodePositions.get(node.agent_id);
    if (!from) return;
    node.peers.forEach(peer => {
      const peerNode = topo.nodes.find(n => n.ip === peer.ip);
      if (!peerNode) return;
      const to = nodePositions.get(peerNode.agent_id);
      if (!to) return;
      edges.push({ x1: from.x, y1: from.y, x2: to.x, y2: to.y });
    });
  });

  return (
    <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-100 bg-gray-50 flex items-center justify-between">
        <span className="text-[11px] font-bold text-gray-500 uppercase tracking-wide">
          Network Topology — {topo.nodes.length} assets · {subnets.length} subnet{subnets.length !== 1 ? "s" : ""}
        </span>
        <div className="flex items-center gap-3 text-[10px] text-gray-500">
          {[["online", "#16a34a"], ["stale", "#d97706"], ["offline", "#9ca3af"]].map(([s, c]) => (
            <div key={s} className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: c }} />
              <span className="capitalize">{s}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="overflow-x-auto">
        <svg width="100%" viewBox={`0 0 ${W} ${totalH}`} className="min-w-[600px]" style={{ height: Math.max(totalH, 200) }}>
          {subnets.map((sub, si) => {
            const y = 50 + si * (SUBNET_H + 40);
            return (
              <g key={sub.subnet}>
                <rect x={20} y={y} width={W - 40} height={SUBNET_H} rx={10}
                  fill={si % 2 === 0 ? "#f8fafc" : "#f1f5f9"} stroke="#e2e8f0" strokeWidth={1} />
                <text x={36} y={y + 18} fontSize={10} fill="#94a3b8" fontWeight={600} fontFamily="monospace">
                  {sub.subnet}.0/24
                </text>
                <text x={W - 40} y={y + 18} fontSize={10} fill="#cbd5e1" textAnchor="end">
                  {sub.count} host{sub.count !== 1 ? "s" : ""}
                </text>
              </g>
            );
          })}
          {edges.map((e, i) => (
            <line key={i} x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2}
              stroke="#cbd5e1" strokeWidth={1} strokeDasharray="4 3" opacity={0.6} />
          ))}
          {topo.nodes.map(node => {
            const pos = nodePositions.get(node.agent_id);
            if (!pos) return null;
            const asset = assetMap.get(node.agent_id);
            const isSelected = selected === node.agent_id;
            const color = STATUS_COLOR[node.status] ?? "#9ca3af";
            const hostname = (asset?.hostname || node.hostname).split(".")[0];
            return (
              <g key={node.agent_id} transform={`translate(${pos.x},${pos.y})`}
                className="cursor-pointer" onClick={() => onSelect(node.agent_id)}>
                {isSelected && (
                  <circle r={NODE_R + 5} fill="none" stroke="#f97316" strokeWidth={2} strokeDasharray="4 2" />
                )}
                <circle r={NODE_R + 1} fill="white" stroke="#e2e8f0" strokeWidth={1} />
                <circle r={NODE_R} fill={isSelected ? "#fff7ed" : "white"} stroke={color} strokeWidth={isSelected ? 2.5 : 1.5} />
                {node.status === "online" && (
                  <circle r={NODE_R + 3} fill="none" stroke={color} strokeWidth={1} opacity={0.3} />
                )}
                <text textAnchor="middle" dominantBaseline="middle" fontSize={18} y={-4}>
                  {getOsIcon(asset?.os ?? "")}
                </text>
                <circle cx={NODE_R - 4} cy={-(NODE_R - 4)} r={5} fill={color} stroke="white" strokeWidth={1.5} />
                <text textAnchor="middle" y={NODE_R + 14} fontSize={10} fill="#374151" fontWeight={600}>
                  {hostname.length > 14 ? hostname.slice(0, 13) + "…" : hostname}
                </text>
                <text textAnchor="middle" y={NODE_R + 26} fontSize={9} fill="#94a3b8" fontFamily="monospace">
                  {node.ip || "—"}
                </text>
                {asset?.cpu_percent != null && (
                  <g transform={`translate(${-NODE_R},${NODE_R + 32})`}>
                    <rect width={NODE_R * 2} height={3} rx={1.5} fill="#f1f5f9" />
                    <rect width={Math.max(2, (asset.cpu_percent / 100) * NODE_R * 2)} height={3} rx={1.5}
                      fill={asset.cpu_percent > 80 ? "#dc2626" : "#2563eb"} />
                  </g>
                )}
              </g>
            );
          })}
        </svg>
      </div>
      {topo.nodes.length === 0 && (
        <div className="py-12 text-center text-gray-400 text-xs">
          No assets with topology data yet.
        </div>
      )}
    </div>
  );
}

// ── KPI card ──────────────────────────────────────────────────────────────────

function KPICard({
  label, value, color, icon, sublabel,
}: {
  label: string; value: number; color: "blue" | "green" | "amber" | "red" | "gray";
  icon?: React.ReactNode; sublabel?: string;
}) {
  const cfg = {
    blue:  { text: "text-blue-600",  bg: "bg-blue-50",  border: "border-blue-100" },
    green: { text: "text-green-600", bg: "bg-green-50", border: "border-green-100" },
    amber: { text: "text-amber-600", bg: "bg-amber-50", border: "border-amber-100" },
    red:   { text: "text-red-600",   bg: "bg-red-50",   border: "border-red-100" },
    gray:  { text: "text-gray-500",  bg: "bg-gray-100", border: "border-gray-200" },
  }[color];

  return (
    <div className={cn("flex items-center gap-3 px-4 py-3 rounded-xl border", cfg.bg, cfg.border)}>
      {icon && (
        <div className={cn("p-2 rounded-lg bg-white/60 shadow-sm", cfg.text)}>{icon}</div>
      )}
      <div>
        <div className={cn("text-xl font-black leading-none tabular-nums", cfg.text)}>{value}</div>
        <div className="text-[10px] text-gray-500 font-semibold mt-0.5">{label}</div>
        {sublabel && <div className="text-[10px] text-gray-400 mt-0.5">{sublabel}</div>}
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AssetRegistry() {
  const [view, setView] = useState<View>("table");
  const [assets, setAssets]     = useState<Asset[]>([]);
  const [topo, setTopo]         = useState<TopoData | null>(null);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState<string | null>(null);
  const [selected, setSelected] = useState<Asset | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch]     = useState("");
  const searchRef = useRef<HTMLInputElement>(null);

  const fetchAssets = useCallback(async () => {
    try {
      const r = await fetch(API);
      if (!r.ok) throw new Error(`${r.status}`);
      setAssets(await r.json());
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchTopo = useCallback(async () => {
    try {
      const r = await fetch(`${API}/topology`);
      if (!r.ok) throw new Error(`${r.status}`);
      setTopo(await r.json());
    } catch {
      // topology is best-effort
    }
  }, []);

  useEffect(() => {
    fetchAssets();
    fetchTopo();
    const t = setInterval(() => { fetchAssets(); fetchTopo(); }, 30_000);
    return () => clearInterval(t);
  }, [fetchAssets, fetchTopo]);

  const handleSelectTopo = (id: string) => {
    const next = selectedId === id ? null : id;
    setSelectedId(next);
    setSelected(next ? (assets.find(x => x.agent_id === next) ?? null) : null);
  };

  const filtered = assets.filter(a =>
    !search || [a.hostname, a.ip, a.mac, a.os, a.asset_tier, a.owner].some(
      v => v?.toLowerCase().includes(search.toLowerCase())
    )
  );

  const online   = assets.filter(a => a.status === "online").length;
  const stale    = assets.filter(a => a.status === "stale").length;
  const offline  = assets.filter(a => a.status === "offline").length;
  const critical = assets.filter(a => a.asset_tier === "critical").length;

  return (
    <div className="space-y-4">

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
        {/* Top gradient stripe */}
        <div className="h-1 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500" />

        <div className="p-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-xl bg-orange-50 border border-orange-100 flex items-center justify-center flex-shrink-0">
                <Monitor className="w-5 h-5 text-orange-500" />
              </div>
              <div>
                <h1 className="text-base font-bold text-gray-900">Asset Registry</h1>
                <p className="text-xs text-gray-500 mt-0.5">
                  Live system inventory · hardware · network · health · CIS Control 1
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <div className="flex items-center border border-gray-200 rounded-xl bg-gray-50 overflow-hidden">
                <button
                  onClick={() => setView("table")}
                  className={cn(
                    "flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold transition-all",
                    view === "table"
                      ? "bg-orange-500 text-white shadow-sm"
                      : "text-gray-500 hover:text-gray-700 hover:bg-white"
                  )}
                >
                  <LayoutGrid className="w-3.5 h-3.5" /> Table
                </button>
                <button
                  onClick={() => setView("topology")}
                  className={cn(
                    "flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold transition-all",
                    view === "topology"
                      ? "bg-orange-500 text-white shadow-sm"
                      : "text-gray-500 hover:text-gray-700 hover:bg-white"
                  )}
                >
                  <Network className="w-3.5 h-3.5" /> Topology
                </button>
              </div>
              <button
                onClick={() => { fetchAssets(); fetchTopo(); }}
                className="p-2 hover:bg-gray-100 rounded-xl transition-colors text-gray-400 hover:text-gray-600"
                title="Refresh"
              >
                <RefreshCw className={cn("w-4 h-4", loading && "animate-spin")} />
              </button>
            </div>
          </div>

          {/* KPI strip */}
          <div className="grid grid-cols-5 gap-2.5 mt-4 pt-4 border-t border-gray-100">
            <KPICard label="Total Assets"  value={assets.length} color="blue"  icon={<Server className="w-4 h-4" />} />
            <KPICard label="Online"        value={online}        color="green" icon={<Activity className="w-4 h-4" />} />
            <KPICard label="Stale"         value={stale}         color="amber" icon={<Clock className="w-4 h-4" />} />
            <KPICard label="Offline"       value={offline}       color="gray"  icon={<Wifi className="w-4 h-4" />} />
            <KPICard label="Critical Tier" value={critical}      color="red"   icon={<Shield className="w-4 h-4" />} />
          </div>
        </div>
      </div>

      {error && (
        <div className="px-4 py-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 flex items-center gap-2">
          <X className="w-3.5 h-3.5 flex-shrink-0" />
          Failed to load assets: {error}
        </div>
      )}

      {/* ── Table view ──────────────────────────────────────────────────────── */}
      {view === "table" && (
        <div className="space-y-3">
          {/* Filter bar */}
          <div className="flex items-center gap-2">
            <div className="relative flex-1 max-w-xs">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400 pointer-events-none" />
              <input
                ref={searchRef}
                type="text"
                placeholder="Search hostname, IP, MAC, OS…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="w-full pl-9 pr-3 py-2 text-xs border border-gray-200 rounded-xl bg-white text-gray-800 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-orange-200 focus:border-orange-300 transition-all"
              />
            </div>
            <span className="text-[10px] text-gray-400 ml-auto font-medium">
              {filtered.length} of {assets.length} · auto-refresh 30s
            </span>
          </div>

          {/* Asset table */}
          <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-gray-100 bg-gray-50">
                  {["Asset", "OS", "IP / MAC", "CPU", "RAM", "Battery", "Processes", "Uptime", "Tier", "Last Seen"].map(h => (
                    <th key={h} className="px-3 py-2.5 text-left text-[10px] font-bold text-gray-400 uppercase tracking-wider whitespace-nowrap">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {loading && assets.length === 0 ? (
                  <tr>
                    <td colSpan={10}>
                      {Array.from({ length: 4 }).map((_, i) => (
                        <div key={i} className="flex gap-3 px-3 py-3 border-b border-gray-50">
                          {Array.from({ length: 10 }).map((_, j) => (
                            <div key={j} className="h-3 bg-gray-100 rounded-full animate-pulse flex-1" />
                          ))}
                        </div>
                      ))}
                    </td>
                  </tr>
                ) : filtered.length === 0 ? (
                  <tr>
                    <td colSpan={10} className="px-4 py-14 text-center">
                      <div className="flex flex-col items-center gap-2 text-gray-400">
                        <Search className="w-6 h-6 text-gray-300" />
                        <p className="text-xs font-medium">
                          {assets.length === 0
                            ? "No agents enrolled yet."
                            : "No assets match your search."}
                        </p>
                      </div>
                    </td>
                  </tr>
                ) : (
                  filtered.map((a, idx) => (
                    <tr
                      key={a.agent_id}
                      onClick={() => setSelected(selected?.agent_id === a.agent_id ? null : a)}
                      className={cn(
                        "border-b border-gray-50 cursor-pointer transition-all group relative",
                        "hover:bg-orange-50/50 hover:shadow-[inset_3px_0_0_#f97316]",
                        selected?.agent_id === a.agent_id && "bg-orange-50 shadow-[inset_3px_0_0_#f97316]"
                      )}
                    >
                      {/* Asset name */}
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-2.5">
                          <div className="relative">
                            <div className="w-8 h-8 rounded-lg bg-gray-100 flex items-center justify-center text-base flex-shrink-0">
                              {getOsIcon(a.os)}
                            </div>
                            <StatusDot status={a.status} />
                          </div>
                          <div>
                            <div className="font-bold text-gray-800 text-[11px] group-hover:text-orange-600 transition-colors">
                              {a.hostname}
                            </div>
                            <div className="text-[9px] text-gray-400 font-mono">{a.agent_id.slice(0, 16)}…</div>
                          </div>
                        </div>
                      </td>
                      {/* OS */}
                      <td className="px-3 py-3 text-gray-600 text-[10px] whitespace-nowrap">
                        <div>{a.os}</div>
                        {a.os_version && <div className="text-gray-400 text-[9px]">{a.os_version}</div>}
                      </td>
                      {/* IP / MAC */}
                      <td className="px-3 py-3">
                        <div className="font-mono text-[10px] text-gray-700">{a.ip || a.last_ip || "—"}</div>
                        <div className="font-mono text-[9px] text-gray-400">{a.mac || "—"}</div>
                      </td>
                      {/* CPU */}
                      <td className="px-3 py-3"><MiniBar value={a.cpu_percent} /></td>
                      {/* RAM */}
                      <td className="px-3 py-3">
                        <MiniBar value={a.mem_percent} color="#7c3aed" />
                        <div className="text-[9px] text-gray-400 mt-0.5">{mb(a.mem_used_mb)} / {mb(a.mem_total_mb)}</div>
                      </td>
                      {/* Battery */}
                      <td className="px-3 py-3">
                        {a.battery_present
                          ? <BatteryIcon pct={a.battery_pct} charging={a.battery_charging} />
                          : <span className="text-[10px] text-gray-300">—</span>}
                      </td>
                      {/* Processes */}
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-1 text-[11px] text-gray-700">
                          <Users className="w-3 h-3 text-gray-400" />
                          <span className="font-bold tabular-nums">{a.process_count || "—"}</span>
                        </div>
                      </td>
                      {/* Uptime */}
                      <td className="px-3 py-3 text-[10px] text-gray-600 whitespace-nowrap font-medium">
                        {uptime(a.uptime_sec)}
                      </td>
                      {/* Tier */}
                      <td className="px-3 py-3"><TierBadge tier={a.asset_tier} /></td>
                      {/* Last seen */}
                      <td className="px-3 py-3 text-[10px] text-gray-500 whitespace-nowrap">
                        <div className="flex items-center gap-1">
                          <span>{elapsed(a.elapsed_s)}</span>
                          <ChevronRight className="w-3 h-3 text-orange-300 group-hover:text-orange-400 transition-colors" />
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Tier summary cards */}
          <div className="grid grid-cols-3 gap-3">
            {(["critical", "important", "standard"] as const).map(tier => {
              const group = assets.filter(a => a.asset_tier === tier);
              const live  = group.filter(a => a.status === "online").length;
              const cfg   = TIER_CONFIG[tier];
              return (
                <div
                  key={tier}
                  className={cn(
                    "bg-white border rounded-xl p-4 shadow-sm border-l-4 transition-all hover:shadow-md",
                    tier === "critical"  ? "border-l-red-500"   :
                    tier === "important" ? "border-l-amber-500" : "border-l-gray-300"
                  )}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className={cn("text-[10px] font-bold uppercase tracking-wider capitalize", cfg.text)}>{tier} Tier</span>
                    <TierBadge tier={tier} />
                  </div>
                  <div className="text-2xl font-black text-gray-900 tabular-nums">{group.length}</div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[10px] text-green-600 font-semibold">{live} online</span>
                    <span className="text-[10px] text-gray-400">·</span>
                    <span className="text-[10px] text-gray-500">{group.length - live} away</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Topology view ───────────────────────────────────────────────────── */}
      {view === "topology" && (
        <div>
          {topo ? (
            <TopologyDiagram
              topo={topo}
              assets={assets}
              onSelect={handleSelectTopo}
              selected={selectedId}
            />
          ) : (
            <div className="bg-white border border-gray-200 rounded-2xl shadow-sm p-16 text-center">
              <div className="w-12 h-12 rounded-2xl bg-gray-100 flex items-center justify-center mx-auto mb-4">
                <Network className="w-6 h-6 text-gray-400" />
              </div>
              <div className="text-sm font-medium text-gray-500">Loading topology…</div>
            </div>
          )}
        </div>
      )}

      {/* ── Asset detail modal (full overlay) ───────────────────────────────── */}
      {selected && (
        <AssetDetailModal
          asset={selected}
          onClose={() => { setSelected(null); setSelectedId(null); }}
        />
      )}
    </div>
  );
}
