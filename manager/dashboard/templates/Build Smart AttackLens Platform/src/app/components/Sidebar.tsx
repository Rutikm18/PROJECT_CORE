import { useState, useEffect, useCallback } from "react";
import {
  AlertTriangle, Terminal, Globe, PackageOpen, Anchor, Users,
  ShieldCheck, Crosshair, BarChart3, Monitor, Database,
  ClipboardList, FlaskConical, LayoutDashboard, Activity,
  Settings, Server, Building2, MapPin,
} from "lucide-react";

export type PageId =
  | "dashboard"
  | "threat-queue"
  | "execution"
  | "network"
  | "vulnerabilities"
  | "persistence"
  | "identity"
  | "security-posture"
  | "compliance"
  | "threat-intel"
  | "timeline"
  | "assets"
  | "raw-data"
  | "accuracy"
  | "settings";

interface NavItem {
  id: PageId;
  label: string;
  icon: React.ElementType;
  // badges are always live — no static values
  badgeColor?: "red" | "amber" | "green";
  badgePulse?: boolean;
  // which category keys map to this nav item (for grouping new-finding counts)
  catKeys?: string[];
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

// Category keyword → PageId mapping (mirrors ThreatQueue catKey logic)
const CAT_MAP: Record<string, PageId> = {
  execution: "execution", malware: "execution", process: "execution",
  script: "execution", binary: "execution",
  network: "network", connection: "network", c2: "network", dns: "network",
  tunnel: "network", beacon: "network",
  package: "vulnerabilities", vuln: "vulnerabilities", cve: "vulnerabilities",
  sbom: "vulnerabilities",
  persistence: "persistence", service: "persistence", task: "persistence",
  config: "persistence", launchd: "persistence", plist: "persistence",
  backdoor: "persistence",
  user: "identity", identity: "identity", account: "identity",
  credential: "identity", keychain: "identity",
  security: "security-posture", posture: "security-posture", sip: "security-posture",
  firewall: "security-posture", gatekeeper: "security-posture",
};

function catToPageId(category: string): PageId {
  const c = category.toLowerCase();
  for (const [key, page] of Object.entries(CAT_MAP)) {
    if (c.includes(key)) return page;
  }
  return "threat-queue"; // fallback
}

const GROUPS: NavGroup[] = [
  {
    label: "Operations",
    items: [
      { id: "dashboard",    label: "Dashboard",  icon: LayoutDashboard },
      { id: "threat-queue", label: "Findings",   icon: AlertTriangle,  badgeColor: "red", badgePulse: true },
    ],
  },
  {
    label: "Detections",
    items: [
      { id: "execution",       label: "Execution & Malware",     icon: Terminal,    badgeColor: "red"   },
      { id: "network",         label: "Network Threats",         icon: Globe,       badgeColor: "red"   },
      { id: "vulnerabilities", label: "Vulnerability Surface",   icon: PackageOpen, badgeColor: "amber" },
      { id: "persistence",     label: "Persistence & Backdoors", icon: Anchor,      badgeColor: "amber" },
      { id: "identity",        label: "Identity & Access",       icon: Users,       badgeColor: "amber" },
    ],
  },
  {
    label: "Posture",
    items: [
      { id: "security-posture", label: "Security Posture", icon: ShieldCheck, badgeColor: "red" },
      { id: "compliance",       label: "CIS Compliance",   icon: ClipboardList },
    ],
  },
  {
    label: "Management",
    items: [
      { id: "threat-intel", label: "Threat Intelligence", icon: Crosshair    },
      { id: "timeline",     label: "Timeline & History",  icon: BarChart3    },
      { id: "assets",       label: "Asset Registry",      icon: Monitor      },
      { id: "raw-data",     label: "Deep Analysis",       icon: Database     },
      { id: "accuracy",     label: "Detection Accuracy",  icon: FlaskConical },
    ],
  },
];

interface SidebarProps {
  activePage: PageId;
  onNavigate: (page: PageId) => void;
}

// Counts keyed by PageId — only status=new findings
type NewCounts = Partial<Record<PageId, number>>;

export function Sidebar({ activePage, onNavigate }: SidebarProps) {
  const [ready,       setReady]       = useState(false);
  const [agentTotal,  setAgentTotal]  = useState<number | null>(null);
  const [agentOnline, setAgentOnline] = useState<number | null>(null);
  const [newCounts,   setNewCounts]   = useState<NewCounts>({});
  const [totalCritical, setTotalCritical] = useState(0);
  const [orgName,     setOrgName]     = useState("");
  const [orgLocation, setOrgLocation] = useState("");

  // Fetch agent fleet status
  const fetchOrgSettings = useCallback(async () => {
    try {
      const r = await fetch("/api/v1/settings");
      if (!r.ok) return;
      const d = await r.json();
      setOrgName(d.settings?.org_name     ?? "");
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

  // Fetch only status=new findings — these are from the latest scan and haven't
  // been touched by an analyst yet. Counts are grouped per nav section.
  const fetchNewCounts = useCallback(async () => {
    try {
      const r = await fetch("/api/v1/soc/findings?status=new&limit=1000&view=active");
      if (!r.ok) return;
      const data: { findings: { category: string; severity: string }[] } = await r.json();
      const findings = data.findings ?? [];

      // Group by target PageId
      const counts: NewCounts = {};
      let critical = 0;
      for (const f of findings) {
        const page = catToPageId(f.category);
        counts[page] = (counts[page] ?? 0) + 1;
        // Also roll up into threat-queue total
        counts["threat-queue"] = (counts["threat-queue"] ?? 0) + 1;
        if (f.severity === "critical") critical++;
      }
      setNewCounts(counts);
      setTotalCritical(critical);
    } catch { /* silent */ }
  }, []);

  useEffect(() => {
    const t = setTimeout(() => setReady(true), 60);
    fetchAgents();
    fetchNewCounts();
    fetchOrgSettings();
    const interval = setInterval(() => {
      fetchAgents();
      fetchNewCounts();
    }, 30_000);
    return () => { clearTimeout(t); clearInterval(interval); };
  }, [fetchAgents, fetchNewCounts, fetchOrgSettings]);

  return (
    <aside
      className="w-[220px] h-screen flex flex-col flex-shrink-0 relative overflow-hidden"
      style={{
        background: "linear-gradient(180deg,#080C12 0%,#0B0F16 55%,#0D1019 100%)",
        borderRight: "1px solid rgba(255,255,255,0.07)",
      }}
    >
      {/* Ambient purple glow at top — matches the logo palette */}
      <div
        aria-hidden
        className="pointer-events-none absolute top-0 left-0 right-0 h-44"
        style={{ background: "radial-gradient(ellipse 75% 65% at 50% -15%,rgba(124,58,237,0.22) 0%,transparent 80%)" }}
      />

      {/* ── Brand / Logo ─────────────────────────────── */}
      <div
        className="relative z-10 px-3 pt-4 pb-3 flex-shrink-0"
        style={{ borderBottom: "1px solid rgba(255,255,255,0.07)" }}
      >
        {/* Shield icon + wordmark */}
        <div className="flex items-center gap-2.5 mb-3.5">
          {/* Shield logo icon with purple glow */}
          <div className="relative flex-shrink-0">
            <img
              src="/static/logo-icon.svg"
              alt="Attacklens"
              className="w-10 h-10 relative z-10 drop-shadow-md al-logo-glow"
              style={{ filter: "drop-shadow(0 0 6px rgba(139,92,246,0.5))" }}
            />
          </div>
          {/* Wordmark */}
          <div className="leading-none min-w-0">
            <div className="font-extrabold text-[14px] tracking-tight leading-none"
              style={{ background: "linear-gradient(90deg,#A78BFA 0%,#8B5CF6 50%,#7C3AED 100%)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
              Attacklens
            </div>
            <div
              className="text-[9px] font-bold mt-[5px] tracking-widest uppercase"
              style={{ color: "rgba(255,255,255,0.72)", letterSpacing: "0.09em" }}
            >
              Continuous Threat Exposure
            </div>
          </div>
        </div>

        {/* Agent fleet status */}
        <div
          className="rounded-lg px-2.5 py-2 mb-2"
          style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.08)" }}
        >
          <div className="flex items-center justify-between mb-1.5">
            <div className="flex items-center gap-1.5">
              <Server className="w-3 h-3 flex-shrink-0" style={{ color: "rgba(255,255,255,0.35)" }} />
              <span className="text-[9px] font-bold uppercase tracking-widest" style={{ color: "rgba(255,255,255,0.35)" }}>
                Agent Fleet
              </span>
            </div>
            <span
              className="text-[8px] font-bold px-1.5 py-0.5 rounded"
              style={{ background: "rgba(74,222,128,0.15)", color: "#4ade80", border: "1px solid rgba(74,222,128,0.2)" }}
            >
              LIVE
            </span>
          </div>

          <div className="flex items-end justify-between gap-2">
            {/* Online count */}
            <div className="flex items-center gap-1.5">
              <div className="relative flex-shrink-0">
                <div className="w-2 h-2 rounded-full bg-green-400" />
                <div className="w-2 h-2 rounded-full bg-green-400 absolute inset-0 al-heartbeat opacity-40" />
              </div>
              <span className="text-[18px] font-black tabular-nums leading-none" style={{ color: "#4ade80" }}>
                {agentOnline ?? "—"}
              </span>
              <span className="text-[9px] font-medium leading-none pb-0.5" style={{ color: "rgba(255,255,255,0.45)" }}>
                online
              </span>
            </div>

            {/* Divider */}
            <div className="w-px h-5 self-center" style={{ background: "rgba(255,255,255,0.1)" }} />

            {/* Total count */}
            <div className="flex items-center gap-1.5">
              <span className="text-[18px] font-black tabular-nums leading-none" style={{ color: "rgba(255,255,255,0.7)" }}>
                {agentTotal ?? "—"}
              </span>
              <span className="text-[9px] font-medium leading-none pb-0.5" style={{ color: "rgba(255,255,255,0.35)" }}>
                total
              </span>
            </div>

            {/* Offline badge */}
            {agentTotal !== null && agentOnline !== null && agentTotal - agentOnline > 0 && (
              <span
                className="text-[8px] font-bold px-1.5 py-0.5 rounded ml-auto"
                style={{ background: "rgba(239,68,68,0.15)", color: "#f87171", border: "1px solid rgba(239,68,68,0.2)" }}
              >
                {agentTotal - agentOnline} offline
              </span>
            )}
          </div>

          {/* Mini bar showing online ratio */}
          {agentTotal !== null && agentTotal > 0 && (
            <div className="mt-2 h-1 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.08)" }}>
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{
                  width: `${Math.round(((agentOnline ?? 0) / agentTotal) * 100)}%`,
                  background: "linear-gradient(90deg,#4ade80,#22c55e)",
                }}
              />
            </div>
          )}
        </div>

        {/* Threat pulse — live new-only counts */}
        <div
          className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg"
          style={{ background: "rgba(124,58,237,0.08)", border: "1px solid rgba(124,58,237,0.15)" }}
        >
          <Activity className="w-3 h-3 flex-shrink-0 al-heartbeat" style={{ color: "#A78BFA" }} />
          <span className="text-[9.5px]" style={{ color: "rgba(255,255,255,0.65)" }}>
            {totalCritical > 0 && (
              <>
                <span style={{ color: "#f87171", fontWeight: 700 }}>{totalCritical} critical</span>
                <span style={{ color: "rgba(255,255,255,0.3)" }}>{" · "}</span>
              </>
            )}
            <span style={{ fontWeight: (newCounts["threat-queue"] ?? 0) > 0 ? 600 : 400 }}>
              {newCounts["threat-queue"] ?? 0} new
            </span>
          </span>
          {(newCounts["threat-queue"] ?? 0) === 0 && (
            <span className="text-[8px] ml-auto" style={{ color: "rgba(255,255,255,0.25)" }}>all clear</span>
          )}
        </div>
      </div>

      {/* ── Navigation ───────────────────────────────── */}
      <nav
        className="relative z-10 flex-1 overflow-y-auto px-2.5 py-3 al-sidebar-nav"
        style={{ scrollbarWidth: "thin", scrollbarColor: "rgba(255,255,255,0.1) transparent" }}
      >
        {GROUPS.map((group, gi) => {
          let itemIdx = GROUPS.slice(0, gi).reduce((s, g) => s + g.items.length, 0);
          return (
            <div key={group.label} className={gi > 0 ? "mt-2" : ""}>
              {/* Group header */}
              <div
                className="flex items-center gap-2 px-2 mb-1.5"
                style={gi > 0 ? { borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: "10px" } : {}}
              >
                <span
                  className="text-[9px] font-bold uppercase tracking-[0.12em]"
                  style={{ color: "rgba(255,255,255,0.25)" }}
                >
                  {group.label}
                </span>
              </div>

              {/* Nav items */}
              {group.items.map((item, ii) => {
                const Icon = item.icon;
                const isActive = activePage === item.id;
                const animDelay = ready ? 0 : (itemIdx + ii) * 45;

                return (
                  <button
                    key={item.id}
                    data-active={isActive ? "true" : undefined}
                    onClick={() => onNavigate(item.id)}
                    className="al-nav-btn w-full flex items-center justify-between gap-2 px-2.5 py-[7px] rounded-lg mb-[2px] cursor-pointer text-left relative overflow-hidden"
                    style={{
                      background: isActive ? "rgba(124,58,237,0.14)" : "transparent",
                      border: `1px solid ${isActive ? "rgba(124,58,237,0.30)" : "transparent"}`,
                      color: isActive ? "#A78BFA" : "rgba(255,255,255,0.52)",
                      animation: ready ? undefined : `al-nav-enter 0.32s ease ${animDelay}ms both`,
                      transition: "background 0.15s ease, border-color 0.15s ease, color 0.15s ease, box-shadow 0.15s ease",
                    }}
                  >
                    {/* Left accent bar (active) */}
                    {isActive && (
                      <span
                        aria-hidden
                        className="absolute left-0 top-1/2 -translate-y-1/2 rounded-r-full"
                        style={{
                          width: "2.5px",
                          height: "16px",
                          background: "#7C3AED",
                          boxShadow: "0 0 10px rgba(124,58,237,0.8), 0 0 4px rgba(139,92,246,1)",
                        }}
                      />
                    )}

                    <div className="flex items-center gap-2.5 pl-1 min-w-0">
                      <Icon
                        className="w-3.5 h-3.5 flex-shrink-0"
                        style={{ color: isActive ? "#A78BFA" : "rgba(255,255,255,0.32)" }}
                      />
                      <span
                        className="text-[11.5px] leading-tight truncate"
                        style={{ fontWeight: isActive ? 600 : 450, letterSpacing: "-0.01em" }}
                      >
                        {item.label}
                      </span>
                    </div>

                    {/* Live badge — only shows count of NEW (unactioned) findings */}
                    {(() => {
                      const count = newCounts[item.id] ?? 0;
                      if (!item.badgeColor || count === 0) return null;
                      const isRed = item.badgeColor === "red";
                      return (
                        <span
                          className="flex-shrink-0 min-w-[18px] text-center tabular-nums px-1.5 py-0.5 text-[9px] font-bold rounded-full"
                          style={
                            isRed
                              ? {
                                  background: "#DC2626",
                                  color: "#fff",
                                  animation: item.badgePulse ? "badge-pulse 1.8s ease-in-out infinite" : undefined,
                                  boxShadow: item.badgePulse ? "0 0 0 0 rgba(220,38,38,0.5)" : undefined,
                                }
                              : {
                                  background: "rgba(217,119,6,0.9)",
                                  color: "#fff",
                                }
                          }
                        >
                          {count}
                        </span>
                      );
                    })()}
                  </button>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* ── Footer / User ────────────────────────────── */}
      <div
        className="relative z-10 p-3 flex-shrink-0"
        style={{ borderTop: "1px solid rgba(255,255,255,0.07)" }}
      >
        {/* Settings row */}
        <button
          onClick={() => onNavigate("settings")}
          data-active={activePage === "settings" ? "true" : undefined}
          className="al-nav-btn w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg mb-2 cursor-pointer text-left"
          style={{
            color: activePage === "settings" ? "#A78BFA" : "rgba(255,255,255,0.38)",
            background: activePage === "settings" ? "rgba(124,58,237,0.14)" : "transparent",
            border: `1px solid ${activePage === "settings" ? "rgba(124,58,237,0.30)" : "transparent"}`,
            transition: "all 0.15s ease",
          }}
        >
          <Settings className="w-3 h-3" style={{ color: activePage === "settings" ? "#A78BFA" : "rgba(255,255,255,0.25)" }} />
          <span className="text-[10.5px] font-medium">Settings</span>
        </button>

        {/* Org card */}
        <div
          className="flex items-center gap-2.5 px-2.5 py-2 rounded-xl"
          style={{
            background: "rgba(255,255,255,0.05)",
            border: "1px solid rgba(255,255,255,0.08)",
          }}
        >
          <div
            className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: "rgba(124,58,237,0.18)", border: "1px solid rgba(124,58,237,0.25)" }}
          >
            <Building2 className="w-3.5 h-3.5" style={{ color: "#A78BFA" }} />
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-[11px] font-semibold truncate leading-tight" style={{ color: "rgba(255,255,255,0.82)" }}>
              {orgName || "Organisation"}
            </div>
            {orgLocation && (
              <div className="flex items-center gap-1 mt-[2px]">
                <MapPin className="w-2.5 h-2.5 flex-shrink-0" style={{ color: "rgba(255,255,255,0.28)" }} />
                <span className="text-[9px] truncate" style={{ color: "rgba(255,255,255,0.35)" }}>
                  {orgLocation}
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
    </aside>
  );
}
