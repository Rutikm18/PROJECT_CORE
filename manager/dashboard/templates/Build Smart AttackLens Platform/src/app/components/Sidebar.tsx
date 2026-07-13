/**
 * Sidebar — dark navigation rail.
 *
 * Uses React Router NavLink so browser URL changes on each click.
 * Active state is derived from useLocation() — no external activePage prop needed.
 *
 * Live badge counts come from the findings API (status=new, polled every 30 s).
 */
import { useState, useEffect, useCallback } from "react";
import { NavLink, useNavigate } from "react-router";
import {
  AlertTriangle, Terminal, Globe, PackageOpen,
  Crosshair, BarChart3, Monitor, Database,
  ClipboardList, LayoutDashboard, Activity,
  Settings, Server, Building2, MapPin, Layers,
  ShieldCheck, GitMerge,
} from "lucide-react";
import { CIS_COMPLIANCE_LIVE } from "../featureFlags";

// ── Route definitions ─────────────────────────────────────────────────────────

interface NavItem {
  label: string;
  to: string;
  icon: React.ElementType;
  badgeColor?: "red" | "amber";
  badgePulse?: boolean;
  catKeys?: string[];
  comingSoon?: boolean;
}

interface NavGroup {
  label: string;
  items: NavItem[];
  comingSoon?: boolean;
}

// Map category keywords → the URL path that owns those findings
const CAT_MAP: Record<string, string> = {
  execution: "/terrain/citadels", malware: "/terrain/citadels",
  process: "/terrain/citadels",   script: "/terrain/citadels",
  lateral: "/terrain/citadels",   covert: "/terrain/citadels",
  persistence: "/terrain/persistence", service: "/terrain/persistence",
  task: "/terrain/persistence",   launchd: "/terrain/persistence",
  plist: "/terrain/persistence",  backdoor: "/terrain/persistence",
  network: "/terrain/vector",     connection: "/terrain/vector",
  c2: "/terrain/vector",          dns: "/terrain/vector",
  tunnel: "/terrain/vector",      beacon: "/terrain/vector",
  port: "/terrain/vector",        arp: "/terrain/vector",
  package: "/terrain/origin",     vuln: "/terrain/origin",
  cve: "/terrain/origin",         sbom: "/terrain/origin",
  config: "/terrain/origin",      binary: "/terrain/origin",
  sysctl: "/terrain/origin",
  user: "/terrain/identity",      identity: "/terrain/identity",
  account: "/terrain/identity",   credential: "/terrain/identity",
  keychain: "/terrain/identity",
  security: "/posture/overview",  posture: "/posture/overview",
  sip: "/posture/overview",       firewall: "/posture/overview",
  gatekeeper: "/posture/overview",
};

function catToPath(category: string): string {
  const c = category.toLowerCase();
  for (const [key, path] of Object.entries(CAT_MAP)) {
    if (c.includes(key)) return path;
  }
  return "/findings";
}

const GROUPS: NavGroup[] = [
  {
    label: "Operations",
    items: [
      { label: "Dashboard",          to: "/dashboard",  icon: LayoutDashboard },
      { label: "Validated Findings", to: "/findings",   icon: AlertTriangle, badgeColor: "red", badgePulse: true },
      { label: "All Incidents",      to: "/incidents",  icon: Layers, badgeColor: "red" },
    ],
  },
  {
    label: "Attack Terrain",
    items: [
      { label: "Origin",    to: "/terrain/origin",      icon: PackageOpen, badgeColor: "amber" },
      { label: "Vector",    to: "/terrain/vector",      icon: Globe,       badgeColor: "red"   },
      { label: "Citadels",  to: "/terrain/citadels",    icon: Terminal,    badgeColor: "red"   },
      // { label: "Persistence & Backdoors", to: "/terrain/persistence", icon: Server },
      // { label: "Identity & Access", to: "/terrain/identity", icon: ShieldCheck },
    ],
  },
  {
    label: "Posture",
    comingSoon: !CIS_COMPLIANCE_LIVE,
    items: [
      // { label: "Security Posture", to: "/posture/overview", icon: Database },
      { label: "CIS Compliance",   to: "/posture/compliance",  icon: ClipboardList, comingSoon: !CIS_COMPLIANCE_LIVE },
    ],
  },
  {
    label: "Intelligence",
    items: [
      { label: "Threat Intelligence", to: "/intelligence/ioc", icon: Crosshair },
    ],
  },
  {
    label: "Inventory & Analysis",
    items: [
      { label: "Timeline & History", to: "/timeline",          icon: BarChart3 },
      { label: "Deep Analysis",      to: "/analysis/deep",         icon: Database  },
      { label: "Custom Rules",  to: "/analysis/custom-rules", icon: GitMerge, comingSoon: true },
      { label: "Asset Registry",     to: "/assets",                icon: Monitor   },
      // { label: "Detection Accuracy", to: "/analysis/accuracy", icon: Activity  },
      // { label: "Detection Coverage", to: "/analysis/coverage", icon: Layers    },
    ],
  },
];

// ── Sidebar component ─────────────────────────────────────────────────────────

type NewCounts = Record<string, number>;

export function Sidebar() {
  const navigate = useNavigate();
  const [ready,        setReady]        = useState(false);
  const [agentTotal,   setAgentTotal]   = useState<number | null>(null);
  const [agentOnline,  setAgentOnline]  = useState<number | null>(null);
  const [newCounts,    setNewCounts]    = useState<NewCounts>({});
  const [totalCritical, setTotalCritical] = useState(0);
  const [orgName,      setOrgName]      = useState("");
  const [orgLocation,  setOrgLocation]  = useState("");

  const fetchOrgSettings = useCallback(async () => {
    try {
      const r = await fetch("/api/v1/settings");
      if (!r.ok) return;
      const d = await r.json();
      setOrgName(d.settings?.org_name ?? "");
      setOrgLocation(d.settings?.org_location ?? "");
    } catch { /* silent */ }
  }, []);

  const fetchAgents = useCallback(async () => {
    try {
      const r = await fetch("/api/v1/agents");
      if (!r.ok) return;
      const agents: { online: boolean }[] = await r.json();
      setAgentTotal(agents.length);
      setAgentOnline(agents.filter(a => a.online).length);
    } catch { /* silent */ }
  }, []);

  const fetchNewCounts = useCallback(async () => {
    try {
      const r = await fetch("/api/v1/soc/findings?status=new&limit=1000&view=active");
      if (!r.ok) return;
      const data: { findings: { category: string; severity: string }[] } = await r.json();
      const findings = data.findings ?? [];
      const counts: NewCounts = {};
      let critical = 0;
      for (const f of findings) {
        const path = catToPath(f.category);
        counts[path] = (counts[path] ?? 0) + 1;
        counts["/findings"] = (counts["/findings"] ?? 0) + 1;
        if (f.severity === "critical") critical++;
      }
      setNewCounts(counts);
      setTotalCritical(critical);
    } catch { /* silent */ }
  }, []);

  useEffect(() => {
    const t = setTimeout(() => setReady(true), 60);
    fetchAgents(); fetchNewCounts(); fetchOrgSettings();
    const iv = setInterval(() => { fetchAgents(); fetchNewCounts(); }, 30_000);
    return () => { clearTimeout(t); clearInterval(iv); };
  }, [fetchAgents, fetchNewCounts, fetchOrgSettings]);

  return (
    <aside
      className="w-[220px] h-screen flex flex-col flex-shrink-0 relative overflow-hidden"
      style={{
        background: "linear-gradient(180deg,#080C12 0%,#0B0F16 55%,#0D1019 100%)",
        borderRight: "1px solid rgba(255,255,255,0.07)",
      }}
    >
      {/* Ambient glow */}
      <div
        aria-hidden
        className="pointer-events-none absolute top-0 left-0 right-0 h-44"
        style={{ background: "radial-gradient(ellipse 75% 65% at 50% -15%,rgba(124,58,237,0.22) 0%,transparent 80%)" }}
      />

      {/* ── Brand ────────────────────────────────────── */}
      <div
        className="relative z-10 px-3 pt-4 pb-3 flex-shrink-0"
        style={{ borderBottom: "1px solid rgba(255,255,255,0.07)" }}
      >
        <NavLink to="/dashboard" className="flex items-center gap-2.5 mb-3.5">
          <div className="relative flex-shrink-0">
            <img src="/static/logo-icon.svg" alt="Attacklens" className="w-10 h-10 relative z-10 drop-shadow-md al-logo-glow"
              style={{ filter: "drop-shadow(0 0 6px rgba(139,92,246,0.5))" }} />
          </div>
          <div className="leading-none min-w-0">
            <div className="font-extrabold text-[14px] tracking-tight leading-none"
              style={{ background: "linear-gradient(90deg,#A78BFA 0%,#8B5CF6 50%,#7C3AED 100%)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
              Attacklens
            </div>
            <div className="text-[9px] font-bold mt-[5px] tracking-widest uppercase"
              style={{ color: "rgba(255,255,255,0.72)", letterSpacing: "0.09em" }}>
              Agentic Exposure Management
            </div>
          </div>
        </NavLink>

        {/* Agent fleet */}
        <div className="rounded-lg px-2.5 py-2 mb-2"
          style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.08)" }}>
          <div className="flex items-center justify-between mb-1.5">
            <div className="flex items-center gap-1.5">
              <Server className="w-3 h-3 flex-shrink-0" style={{ color: "rgba(255,255,255,0.35)" }} />
              <span className="text-[9px] font-bold uppercase tracking-widest" style={{ color: "rgba(255,255,255,0.35)" }}>
                Agent Fleet
              </span>
            </div>
            <span className="text-[8px] font-bold px-1.5 py-0.5 rounded"
              style={{ background: "rgba(74,222,128,0.15)", color: "#4ade80", border: "1px solid rgba(74,222,128,0.2)" }}>
              LIVE
            </span>
          </div>
          <div className="flex items-end justify-between gap-2">
            <div className="flex items-center gap-1.5">
              <div className="relative flex-shrink-0">
                <div className="w-2 h-2 rounded-full bg-green-400" />
                <div className="w-2 h-2 rounded-full bg-green-400 absolute inset-0 al-heartbeat opacity-40" />
              </div>
              <span className="text-[18px] font-black tabular-nums leading-none" style={{ color: "#4ade80" }}>
                {agentOnline ?? "—"}
              </span>
              <span className="text-[9px] font-medium leading-none pb-0.5" style={{ color: "rgba(255,255,255,0.45)" }}>online</span>
            </div>
            <div className="w-px h-5 self-center" style={{ background: "rgba(255,255,255,0.1)" }} />
            <div className="flex items-center gap-1.5">
              <span className="text-[18px] font-black tabular-nums leading-none" style={{ color: "rgba(255,255,255,0.7)" }}>
                {agentTotal ?? "—"}
              </span>
              <span className="text-[9px] font-medium leading-none pb-0.5" style={{ color: "rgba(255,255,255,0.35)" }}>total</span>
            </div>
            {agentTotal !== null && agentOnline !== null && agentTotal - agentOnline > 0 && (
              <span className="text-[8px] font-bold px-1.5 py-0.5 rounded ml-auto"
                style={{ background: "rgba(239,68,68,0.15)", color: "#f87171", border: "1px solid rgba(239,68,68,0.2)" }}>
                {agentTotal - agentOnline} offline
              </span>
            )}
          </div>
          {agentTotal !== null && agentTotal > 0 && (
            <div className="mt-2 h-1 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.08)" }}>
              <div className="h-full rounded-full transition-all duration-700"
                style={{ width: `${Math.round(((agentOnline ?? 0) / agentTotal) * 100)}%`, background: "linear-gradient(90deg,#4ade80,#22c55e)" }} />
            </div>
          )}
        </div>

        {/* Threat pulse */}
        <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg"
          style={{ background: "rgba(124,58,237,0.08)", border: "1px solid rgba(124,58,237,0.15)" }}>
          <Activity className="w-3 h-3 flex-shrink-0 al-heartbeat" style={{ color: "#A78BFA" }} />
          <span className="text-[9.5px]" style={{ color: "rgba(255,255,255,0.65)" }}>
            {totalCritical > 0 && (
              <>
                <span style={{ color: "#f87171", fontWeight: 700 }}>{totalCritical} critical</span>
                <span style={{ color: "rgba(255,255,255,0.3)" }}>{" · "}</span>
              </>
            )}
            <span style={{ fontWeight: (newCounts["/findings"] ?? 0) > 0 ? 600 : 400 }}>
              {newCounts["/findings"] ?? 0} new
            </span>
          </span>
          {(newCounts["/findings"] ?? 0) === 0 && (
            <span className="text-[8px] ml-auto" style={{ color: "rgba(255,255,255,0.25)" }}>all clear</span>
          )}
        </div>
      </div>

      {/* ── Nav ──────────────────────────────────────── */}
      <nav
        className="relative z-10 flex-1 overflow-y-auto px-2.5 py-3 al-sidebar-nav"
        style={{ scrollbarWidth: "thin", scrollbarColor: "rgba(255,255,255,0.1) transparent" }}
      >
        {GROUPS.map((group, gi) => {
          let itemIdx = GROUPS.slice(0, gi).reduce((s, g) => s + g.items.length, 0);
          return (
            <div key={group.label} className={gi > 0 ? "mt-2" : ""}>
              <div
                className="flex items-center gap-2 px-2 mb-1.5"
                style={gi > 0 ? { borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: "10px" } : {}}
              >
                <span className="text-[9px] font-bold uppercase tracking-[0.12em]" style={{ color: "rgba(255,255,255,0.25)" }}>
                  {group.label}
                </span>
                {group.comingSoon && (
                  <span className="px-1.5 py-[1px] text-[8px] font-bold uppercase tracking-wide rounded-full"
                    style={{ background: "rgba(217,119,6,0.18)", color: "rgba(252,211,77,0.9)" }}>
                    Soon
                  </span>
                )}
              </div>

              {group.items.map((item, ii) => {
                const Icon = item.icon;
                const animDelay = ready ? 0 : (itemIdx + ii) * 45;
                const count = newCounts[item.to] ?? 0;

                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    className={({ isActive }) =>
                      [
                        "al-nav-btn w-full flex items-start justify-between gap-2 px-2.5 py-2 rounded-lg mb-[2px] cursor-pointer text-left relative overflow-hidden",
                        isActive
                          ? "bg-[rgba(124,58,237,0.14)] border border-[rgba(124,58,237,0.30)] text-[#A78BFA]"
                          : "border border-transparent text-[rgba(255,255,255,0.52)]",
                      ].join(" ")
                    }
                    style={{ animation: ready ? undefined : `al-nav-enter 0.32s ease ${animDelay}ms both` }}
                  >
                    {({ isActive }) => (
                      <>
                        {isActive && (
                          <span
                            aria-hidden
                            className="absolute left-0 top-[6px] rounded-r-full"
                            style={{ width: "2.5px", height: "16px", background: "#7C3AED",
                              boxShadow: "0 0 10px rgba(124,58,237,0.8), 0 0 4px rgba(139,92,246,1)" }} />
                        )}
                        <div className="flex items-start gap-2.5 pl-1 min-w-0">
                          <Icon className="w-3.5 h-3.5 flex-shrink-0 mt-[1px]"
                            style={{ color: isActive ? "#A78BFA" : "rgba(255,255,255,0.32)" }} />
                          <span className="text-[11px] leading-snug break-words"
                            style={{ fontWeight: isActive ? 600 : 450, letterSpacing: "-0.01em" }}>
                            {item.label}
                          </span>
                        </div>
                        {item.comingSoon && (
                          <span className="flex-shrink-0 px-1.5 py-0.5 text-[8px] font-bold uppercase tracking-wide rounded-full"
                            style={{ background: "rgba(217,119,6,0.18)", color: "rgba(252,211,77,0.9)" }}>
                            Soon
                          </span>
                        )}
                        {item.badgeColor && count > 0 && (
                          <span
                            className="flex-shrink-0 min-w-[18px] text-center tabular-nums px-1.5 py-0.5 text-[9px] font-bold rounded-full"
                            style={item.badgeColor === "red"
                              ? { background: "#DC2626", color: "#fff",
                                  animation: item.badgePulse ? "badge-pulse 1.8s ease-in-out infinite" : undefined,
                                  boxShadow: item.badgePulse ? "0 0 0 0 rgba(220,38,38,0.5)" : undefined }
                              : { background: "rgba(217,119,6,0.9)", color: "#fff" }}
                          >
                            {count}
                          </span>
                        )}
                      </>
                    )}
                  </NavLink>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* ── Footer ───────────────────────────────────── */}
      <div className="relative z-10 p-3 flex-shrink-0" style={{ borderTop: "1px solid rgba(255,255,255,0.07)" }}>
        <NavLink
          to="/settings/org"
          className={({ isActive }) =>
            [
              "al-nav-btn w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg mb-2 cursor-pointer text-left",
              isActive
                ? "text-[#A78BFA] bg-[rgba(124,58,237,0.14)] border border-[rgba(124,58,237,0.30)]"
                : "text-[rgba(255,255,255,0.38)] border border-transparent",
            ].join(" ")
          }
          style={{ transition: "all 0.15s ease" }}
        >
          {({ isActive }) => (
            <>
              <Settings className="w-3 h-3" style={{ color: isActive ? "#A78BFA" : "rgba(255,255,255,0.25)" }} />
              <span className="text-[10.5px] font-medium">Settings</span>
            </>
          )}
        </NavLink>

        {/* Org card */}
        <div className="flex items-center gap-2.5 px-2.5 py-2 rounded-xl"
          style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.08)" }}>
          <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: "rgba(124,58,237,0.18)", border: "1px solid rgba(124,58,237,0.25)" }}>
            <Building2 className="w-3.5 h-3.5" style={{ color: "#A78BFA" }} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-[11px] font-semibold truncate leading-tight" style={{ color: "rgba(255,255,255,0.82)" }}>
              {orgName || "Organisation"}
            </div>
            {orgLocation && (
              <div className="flex items-center gap-1 mt-[2px]">
                <MapPin className="w-2.5 h-2.5 flex-shrink-0" style={{ color: "rgba(255,255,255,0.28)" }} />
                <span className="text-[9px] truncate" style={{ color: "rgba(255,255,255,0.35)" }}>{orgLocation}</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </aside>
  );
}

// Keep backward-compat PageId export for any consumers not yet migrated.
export type PageId = string;
