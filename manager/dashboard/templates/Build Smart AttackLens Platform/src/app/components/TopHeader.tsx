/**
 * TopHeader — command-centre header for AttackLens SOC platform.
 *
 * Three zones:
 *   LEFT    — shield logo · brand word-mark · breadcrumb path
 *   CENTRE  — live threat severity counts · agent health pulse
 *   RIGHT   — UTC clock · ⌘K global search · notifications · user menu
 *
 * Data polled:
 *   /api/v1/attacklens/header-stats  →  { critical, high, medium }
 *   /api/v1/agents/                  →  agent list → online count
 */
import { useState, useEffect, useCallback, useRef } from "react";
import { useLocation, useNavigate } from "react-router";
import {
  Bell, ChevronDown, Clock, LogOut,
  Search, Users, X, LayoutDashboard,
  AlertTriangle, Zap, CheckCircle2,
  Settings, ChevronRight,
} from "lucide-react";
import { useRBAC, type Role } from "../context/RBACContext";
import { useAuth } from "../context/AuthContext";
import { cn } from "../../lib/utils";
import { useTimezone, tzAbbr, fmtTime, fmtDate, initTimezone } from "../context/timezoneStore";
import { TimeRangePicker, isTimeAwareRoute } from "./TimeRangePicker";

// ── Breadcrumb ────────────────────────────────────────────────────────────────

const SEG: Record<string, string> = {
  dashboard: "Security Dashboard", findings: "Validated Findings",
  incidents: "All Incidents", terrain: "Attack Terrain",
  origin: "Origin", vector: "Vector", citadels: "Citadels",
  persistence: "Persistence & Backdoors", identity: "Identity & Access",
  posture: "Posture", overview: "Security Posture", compliance: "CIS Compliance",
  intelligence: "Threat Intelligence", ioc: "IOC Triage", cve: "CVE Intel",
  kev: "KEV Mandates", hunt: "Hunt Queries", feeds: "Feed Status",
  assets: "Asset Registry", timeline: "Timeline & History",
  analysis: "Analysis", deep: "Deep Analysis", deepmesh: "DeepMesh",
  accuracy: "Detection Accuracy",
  coverage: "Detection Coverage", "custom-rules": "Custom Rules",
  settings: "Settings", org: "Organisation", license: "License",
  roles: "Roles", platform: "Platform", validation: "Validation",
  retention: "Data Retention", ai: "AI Configuration",
  notifications: "Notifications", integrations: "Integrations",
};
const crumbs = (path: string) =>
  path.split("/").filter(Boolean).map(p => SEG[p] ?? p);

// ── Command palette routes ────────────────────────────────────────────────────

const CMD = [
  { label: "Security Dashboard",    path: "/",                      group: "Navigate" },
  { label: "All Incidents",         path: "/incidents",             group: "Navigate" },
  { label: "Origin — Packages",     path: "/terrain/origin",        group: "Attack Terrain" },
  { label: "Vector — Network",      path: "/terrain/vector",        group: "Attack Terrain" },
  { label: "Citadels — Execution",  path: "/terrain/citadels",      group: "Attack Terrain" },
  { label: "Identity & Access",     path: "/identity",              group: "Navigate" },
  { label: "Security Posture",      path: "/posture/overview",      group: "Navigate" },
  { label: "CIS Compliance",        path: "/posture/compliance",    group: "Navigate" },
  { label: "IOC Triage",           path: "/intelligence/ioc",      group: "Intelligence" },
  { label: "CVE Intel",            path: "/intelligence/cve",      group: "Intelligence" },
  { label: "KEV Mandates",         path: "/intelligence/kev",      group: "Intelligence" },
  { label: "Hunt Queries",         path: "/intelligence/hunt",     group: "Intelligence" },
  { label: "Feed Status",          path: "/intelligence/feeds",    group: "Intelligence" },
  { label: "Asset Registry",       path: "/assets",                group: "Navigate" },
  { label: "Timeline & History",   path: "/timeline",              group: "Navigate" },
  { label: "Deep Analysis",        path: "/analysis/deep",         group: "Analysis" },
  { label: "DeepMesh (Beta)",      path: "/analysis/deepmesh",     group: "Analysis" },
  { label: "Detection Accuracy",   path: "/analysis/accuracy",     group: "Analysis" },
  { label: "Detection Coverage",   path: "/analysis/coverage",     group: "Analysis" },
  { label: "Custom Rules",          path: "/analysis/custom-rules", group: "Analysis" },
  { label: "Settings",             path: "/settings",              group: "Navigate" },
];

// ── RBAC display ──────────────────────────────────────────────────────────────

const ROLE_STYLE: Record<Role, { badge: string; dot: string; avatar: string }> = {
  admin:   { badge: "bg-red-50 text-red-700 border-red-200",     dot: "bg-red-500",   avatar: "from-red-500 to-red-700" },
  analyst: { badge: "bg-blue-50 text-blue-700 border-blue-200",  dot: "bg-blue-500",  avatar: "from-blue-500 to-indigo-600" },
  viewer:  { badge: "bg-gray-100 text-gray-600 border-gray-200", dot: "bg-gray-400",  avatar: "from-gray-400 to-gray-600" },
};
const ROLE_ICON: Record<Role, string> = { admin: "🔐", analyst: "🔍", viewer: "👁" };
const ROLE_DESC: Record<Role, string> = {
  admin:   "Full access + key management",
  analyst: "Triage, update & comment",
  viewer:  "Read-only view",
};

// ── Severity pill ─────────────────────────────────────────────────────────────

function SevPill({ n, sev, loading }: { n: number; sev: "critical" | "high" | "medium"; loading: boolean }) {
  if (loading) return (
    <div className="flex items-center gap-1 px-2 py-0.5 rounded-md border border-gray-100 bg-gray-50">
      <div className="w-8 h-2.5 bg-gray-200 rounded animate-pulse" />
    </div>
  );
  if (n === 0) return null;

  const c = {
    critical: { wrap: "bg-red-50 border-red-200 text-red-700",     dot: "bg-red-500",   label: "Critical" },
    high:     { wrap: "bg-amber-50 border-amber-200 text-amber-700", dot: "bg-amber-500", label: "High" },
    medium:   { wrap: "bg-yellow-50 border-yellow-100 text-yellow-700", dot: "bg-yellow-400", label: "Med" },
  }[sev];

  return (
    <div className={cn("flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[10px] font-bold select-none", c.wrap)}>
      <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", c.dot, sev === "critical" && "animate-pulse")} />
      <span className="tabular-nums leading-none">{n}</span>
      <span className="opacity-60 font-semibold">{c.label}</span>
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export function TopHeader() {
  const { user, setRole } = useRBAC();
  const { logout, user: authUser } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  // ── Timezone-aware clock ──────────────────────────────────────────────────
  const timezone = useTimezone();

  // Sync authoritative timezone from server once on mount (non-blocking).
  // initTimezone() is also called in main.tsx; this is a belt-and-suspenders
  // guard so any component mount after a cold-cache still self-corrects.
  useEffect(() => { void initTimezone(); }, []); // one-time, stable fn ref

  const [time,    setTime]    = useState(() => fmtTime(timezone));
  const [dateStr, setDateStr] = useState(() => fmtDate(timezone));

  useEffect(() => {
    // Reset immediately when timezone changes, then keep ticking
    setTime(fmtTime(timezone));
    setDateStr(fmtDate(timezone));
    const t = setInterval(() => {
      setTime(fmtTime(timezone));
      setDateStr(fmtDate(timezone));
    }, 1000);
    return () => clearInterval(t);
  }, [timezone]); // re-runs on timezone change

  // ── Threat counts ─────────────────────────────────────────────────────────
  const [threats, setThreats] = useState({ critical: 0, high: 0, medium: 0 });
  const [threatsLoading, setThreatsLoading] = useState(true);

  const fetchThreats = useCallback(async () => {
    try {
      const r = await fetch("/api/v1/attacklens/header-stats");
      if (!r.ok) return;
      const d = await r.json();
      setThreats(d);
    } catch { /* best-effort */ } finally { setThreatsLoading(false); }
  }, []);

  useEffect(() => { fetchThreats(); const t = setInterval(fetchThreats, 120_000); return () => clearInterval(t); }, [fetchThreats]);

  // ── Agent health ──────────────────────────────────────────────────────────
  const [agents, setAgents] = useState({ online: 0, total: 0, loading: true });

  const fetchAgents = useCallback(async () => {
    try {
      const r = await fetch("/api/v1/agents");
      if (!r.ok) return;
      const list: { last_seen?: number; status?: string }[] = await r.json();
      const now = Date.now() / 1000;
      const online = list.filter(a => a.status === "online" || (a.last_seen && now - a.last_seen < 300)).length;
      setAgents({ online, total: list.length, loading: false });
    } catch { setAgents(p => ({ ...p, loading: false })); }
  }, []);

  useEffect(() => { fetchAgents(); const t = setInterval(fetchAgents, 30_000); return () => clearInterval(t); }, [fetchAgents]);

  // ── UI panels ─────────────────────────────────────────────────────────────
  const [userMenuOpen, setUserMenuOpen]   = useState(false);
  const [notifOpen,    setNotifOpen]      = useState(false);
  const [cmdOpen,      setCmdOpen]        = useState(false);
  const [cmdQuery,     setCmdQuery]       = useState("");
  const [cmdIdx,       setCmdIdx]         = useState(0);
  const cmdInputRef = useRef<HTMLInputElement>(null);

  // close all panels
  const closeAll = useCallback(() => { setUserMenuOpen(false); setNotifOpen(false); }, []);

  // ⌘K keyboard shortcut
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault(); setCmdOpen(o => !o); setCmdQuery(""); setCmdIdx(0);
      }
      if (e.key === "Escape") { setCmdOpen(false); closeAll(); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [closeAll]);

  useEffect(() => { if (cmdOpen) setTimeout(() => cmdInputRef.current?.focus(), 50); }, [cmdOpen]);

  // filtered command list
  const filtered = CMD.filter(c =>
    !cmdQuery || c.label.toLowerCase().includes(cmdQuery.toLowerCase()) || c.group.toLowerCase().includes(cmdQuery.toLowerCase())
  );

  const runCmd = (path: string) => { navigate(path); setCmdOpen(false); setCmdQuery(""); };

  const handleCmdKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setCmdIdx(i => Math.min(i + 1, filtered.length - 1)); }
    if (e.key === "ArrowUp")   { e.preventDefault(); setCmdIdx(i => Math.max(i - 1, 0)); }
    if (e.key === "Enter"  && filtered[cmdIdx]) runCmd(filtered[cmdIdx].path);
  };

  // breadcrumb
  const bc = crumbs(location.pathname);
  const pageLabel = bc[bc.length - 1] ?? "Dashboard";

  // threat score summary
  const totalActive = threats.critical + threats.high + threats.medium;
  const threatLevel = threats.critical > 0 ? "critical" : threats.high > 0 ? "high" : threats.medium > 0 ? "medium" : "clean";
  const allAgentsGreen = !agents.loading && agents.online === agents.total && agents.total > 0;

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <>
      {/* ── Main header bar ──────────────────────────────────────────────── */}
      <div
        className="h-11 flex items-center justify-between px-4 flex-shrink-0 relative z-30"
        style={{
          background: "rgba(255,255,255,0.97)",
          borderBottom: "1px solid rgba(0,0,0,0.07)",
          boxShadow: "0 1px 12px rgba(0,0,0,0.06)",
          backdropFilter: "blur(16px)",
        }}
        onClick={closeAll}
      >
        {/* Threat-level scan line (bottom of header) */}
        <div className={cn(
          "absolute bottom-0 left-0 right-0 h-[2px] transition-all duration-1000",
          threatLevel === "critical" ? "bg-gradient-to-r from-red-500 via-red-400 to-orange-500 opacity-70" :
          threatLevel === "high"     ? "bg-gradient-to-r from-amber-500 via-amber-400 to-orange-400 opacity-60" :
          threatLevel === "medium"   ? "bg-gradient-to-r from-yellow-400 via-amber-300 to-yellow-400 opacity-50" :
                                       "bg-gradient-to-r from-emerald-400 via-green-300 to-teal-400 opacity-40"
        )} />

        {/* ── LEFT: brand + breadcrumb ─────────────────────────────────── */}
        <div className="flex items-center gap-2 min-w-0 flex-1" onClick={e => e.stopPropagation()}>
          {/* Logo mark */}
          <div className="flex items-center flex-shrink-0">
            <span className="text-[12px] font-bold tracking-tight text-gray-900 select-none">
              AttackLens
            </span>
          </div>

          {/* Breadcrumb */}
          <div className="flex items-center gap-0.5 min-w-0">
            {bc.map((crumb, i) => (
              <span key={i} className="flex items-center gap-0.5 min-w-0">
                <ChevronRight className="w-3 h-3 text-gray-300 flex-shrink-0" />
                <span className={cn(
                  "truncate",
                  i === bc.length - 1
                    ? "text-[11px] font-semibold text-gray-800"
                    : "text-[10px] text-gray-400 hidden md:block"
                )}>
                  {crumb}
                </span>
              </span>
            ))}
          </div>
        </div>

        {/* ── CENTRE: live threat intelligence ─────────────────────────── */}
        <div className="flex items-center gap-1.5 px-3" onClick={e => e.stopPropagation()}>
          <SevPill n={threats.critical} sev="critical" loading={threatsLoading} />
          <SevPill n={threats.high}     sev="high"     loading={threatsLoading} />
          <SevPill n={threats.medium}   sev="medium"   loading={threatsLoading} />

          {!threatsLoading && totalActive === 0 && (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-emerald-200 bg-emerald-50 text-[10px] font-bold text-emerald-700">
              <CheckCircle2 className="w-3 h-3" />No active threats
            </div>
          )}

          {/* Separator */}
          <div className="w-px h-4 bg-gray-200 mx-1 hidden lg:block" />

          {/* Agent health */}
          {!agents.loading && agents.total > 0 && (
            <div className={cn(
              "items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[10px] font-semibold hidden lg:flex",
              allAgentsGreen
                ? "bg-emerald-50 border-emerald-200 text-emerald-700"
                : "bg-amber-50 border-amber-200 text-amber-700"
            )}>
              <span className={cn(
                "w-1.5 h-1.5 rounded-full",
                allAgentsGreen ? "bg-emerald-500 al-dot-breathe" : "bg-amber-500 animate-pulse"
              )} />
              <Users className="w-3 h-3" />
              <span className="tabular-nums">{agents.online}/{agents.total}</span>
              <span className="opacity-70">agents</span>
            </div>
          )}
        </div>

        {/* ── RIGHT: controls ─────────────────────────────────────────────── */}
        <div className="flex items-center gap-0.5 flex-shrink-0" onClick={e => e.stopPropagation()}>

          {/* Time range picker (hidden on non-time-aware pages) */}
          {isTimeAwareRoute(location.pathname) && (
            <div className="mr-1">
              <TimeRangePicker />
            </div>
          )}

          {/* Live indicator */}
          <div className="flex items-center gap-1 px-2 py-1 rounded-lg mr-1"
            style={{ background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.18)" }}>
            <span className="w-1.5 h-1.5 rounded-full al-dot-breathe" style={{ background: "#10b981" }} />
            <span className="text-[9px] font-bold hidden sm:block" style={{ color: "#059669" }}>LIVE</span>
          </div>

          {/* Timezone clock */}
          <div className="flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-mono text-gray-500 hidden md:flex" title={timezone}>
            <Clock className="w-3 h-3" />
            <span>{dateStr}</span>
            <span className="font-semibold text-gray-700">{time}</span>
            <span className="text-[9px] text-gray-400 font-sans font-semibold">{tzAbbr(timezone)}</span>
          </div>

          {/* ⌘K search */}
          <button
            onClick={() => { setCmdOpen(true); setCmdQuery(""); setCmdIdx(0); }}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-gray-200 bg-gray-50 hover:bg-white hover:border-orange-300 text-[10px] text-gray-500 hover:text-gray-700 transition-all group ml-1"
            title="Global search (⌘K)"
          >
            <Search className="w-3 h-3 group-hover:text-orange-500 transition-colors" />
            <span className="hidden lg:block">Search</span>
            <kbd className="hidden lg:flex items-center gap-0.5 px-1 py-0.5 rounded text-[8px] font-bold bg-gray-200 text-gray-500 leading-none">⌘K</kbd>
          </button>

          {/* Notification bell */}
          <button
            onClick={e => { e.stopPropagation(); setNotifOpen(o => !o); setUserMenuOpen(false); }}
            className="relative p-2 rounded-lg hover:bg-gray-100 transition-colors text-gray-400 hover:text-gray-600"
            title="Notifications"
          >
            <Bell className="w-4 h-4" />
            {threats.critical > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-red-500 ring-2 ring-white animate-pulse" />
            )}
          </button>

          {/* User menu button */}
          <button
            onClick={e => { e.stopPropagation(); setUserMenuOpen(o => !o); setNotifOpen(false); }}
            className={cn(
              "flex items-center gap-1.5 pl-1 pr-2 py-1 rounded-lg border transition-all ml-0.5",
              userMenuOpen
                ? "bg-gray-100 border-gray-300"
                : "border-transparent hover:bg-gray-50 hover:border-gray-200"
            )}
          >
            {/* Avatar */}
            <div className={cn(
              "w-6 h-6 rounded-full flex items-center justify-center text-[9px] font-black text-white shadow-sm bg-gradient-to-br",
              ROLE_STYLE[user.role].avatar
            )}>
              {user.initials}
            </div>
            {/* Name + role badge (desktop only) */}
            <div className="hidden lg:flex items-center gap-1.5">
              <span className="text-[10px] font-semibold text-gray-700 leading-none">
                {authUser?.email?.split("@")[0] ?? user.name}
              </span>
              <span className={cn("px-1.5 py-0.5 rounded text-[8px] font-bold border leading-none", ROLE_STYLE[user.role].badge)}>
                {ROLE_ICON[user.role]} {user.role.toUpperCase()}
              </span>
            </div>
            <ChevronDown className={cn("w-3 h-3 text-gray-400 transition-transform hidden lg:block", userMenuOpen && "rotate-180")} />
          </button>
        </div>
      </div>

      {/* ── User menu dropdown ────────────────────────────────────────────── */}
      {userMenuOpen && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setUserMenuOpen(false)} />
          <div className="fixed right-3 top-12 z-50 w-64 bg-white rounded-2xl border border-gray-200 shadow-xl overflow-hidden"
            style={{ boxShadow: "0 8px 32px rgba(0,0,0,0.12), 0 2px 8px rgba(0,0,0,0.08)" }}>

            {/* User info header */}
            <div className="px-4 py-3.5 border-b border-gray-100 bg-gradient-to-br from-gray-50 to-white">
              <div className="flex items-center gap-3">
                <div className={cn("w-9 h-9 rounded-xl flex items-center justify-center text-[11px] font-black text-white shadow-sm bg-gradient-to-br flex-shrink-0", ROLE_STYLE[user.role].avatar)}>
                  {user.initials}
                </div>
                <div className="min-w-0">
                  <div className="text-[11px] font-bold text-gray-800 truncate">
                    {authUser?.email?.split("@")[0] ?? user.name}
                  </div>
                  <div className="text-[9px] text-gray-400 truncate">
                    {authUser?.email ?? "attacklens.ai"}
                  </div>
                </div>
              </div>
            </div>

            {/* Role switcher */}
            <div className="px-3 pt-2.5 pb-1">
              <div className="text-[9px] font-bold text-gray-400 uppercase tracking-wider px-1 mb-1.5">Switch Role</div>
              {(["admin", "analyst", "viewer"] as Role[]).map(r => (
                <button key={r}
                  onClick={() => { setRole(r); setUserMenuOpen(false); }}
                  className={cn(
                    "w-full flex items-center gap-2.5 px-2.5 py-2 rounded-xl text-left transition-all mb-0.5",
                    user.role === r
                      ? "bg-orange-50 border border-orange-200"
                      : "hover:bg-gray-50 border border-transparent"
                  )}>
                  <div className={cn("w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0", ROLE_STYLE[r].dot.replace("bg-", "bg-") + " opacity-90")}>
                    <span className="text-[8px]">{ROLE_ICON[r]}</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className={cn("text-[10px] font-bold capitalize", user.role === r ? "text-orange-700" : "text-gray-700")}>{r}</div>
                    <div className="text-[9px] text-gray-400 leading-snug truncate">{ROLE_DESC[r]}</div>
                  </div>
                  {user.role === r && <CheckCircle2 className="w-3.5 h-3.5 text-orange-500 flex-shrink-0" />}
                </button>
              ))}
            </div>

            {/* Actions */}
            <div className="px-3 pt-1 pb-2.5 border-t border-gray-100 mt-1 space-y-0.5">
              <button
                onClick={() => { navigate("/settings"); setUserMenuOpen(false); }}
                className="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-xl text-left hover:bg-gray-50 transition-colors"
              >
                <Settings className="w-3.5 h-3.5 text-gray-400" />
                <span className="text-[10px] font-semibold text-gray-700">Settings</span>
              </button>
              <button
                onClick={() => { logout(); setUserMenuOpen(false); }}
                className="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-xl text-left hover:bg-red-50 transition-colors group"
              >
                <LogOut className="w-3.5 h-3.5 text-gray-400 group-hover:text-red-500 transition-colors" />
                <span className="text-[10px] font-semibold text-gray-700 group-hover:text-red-600 transition-colors">Sign Out</span>
              </button>
            </div>
          </div>
        </>
      )}

      {/* ── Notifications panel ───────────────────────────────────────────── */}
      {notifOpen && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setNotifOpen(false)} />
          <div className="fixed right-14 top-12 z-50 w-80 bg-white rounded-2xl border border-gray-200 shadow-xl overflow-hidden"
            style={{ boxShadow: "0 8px 32px rgba(0,0,0,0.12)" }}>

            <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
              <div className="flex items-center gap-2">
                <Bell className="w-3.5 h-3.5 text-orange-500" />
                <span className="text-[11px] font-bold text-gray-800">Notifications</span>
              </div>
              <button onClick={() => setNotifOpen(false)} className="p-0.5 hover:bg-gray-100 rounded-lg transition-colors">
                <X className="w-3.5 h-3.5 text-gray-400" />
              </button>
            </div>

            <div className="divide-y divide-gray-50">
              {threats.critical > 0 && (
                <button
                  onClick={() => { navigate("/incidents"); setNotifOpen(false); }}
                  className="w-full flex items-start gap-3 px-4 py-3 hover:bg-red-50 transition-colors text-left"
                >
                  <div className="w-7 h-7 rounded-xl bg-red-100 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-red-600" />
                  </div>
                  <div>
                    <div className="text-[10px] font-bold text-gray-800">{threats.critical} Critical finding{threats.critical > 1 ? "s" : ""} active</div>
                    <div className="text-[9px] text-gray-500 mt-0.5">Requires immediate attention — view in All Incidents</div>
                  </div>
                </button>
              )}
              {threats.high > 0 && (
                <button
                  onClick={() => { navigate("/incidents"); setNotifOpen(false); }}
                  className="w-full flex items-start gap-3 px-4 py-3 hover:bg-amber-50 transition-colors text-left"
                >
                  <div className="w-7 h-7 rounded-xl bg-amber-100 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Zap className="w-3.5 h-3.5 text-amber-600" />
                  </div>
                  <div>
                    <div className="text-[10px] font-bold text-gray-800">{threats.high} High severity finding{threats.high > 1 ? "s" : ""}</div>
                    <div className="text-[9px] text-gray-500 mt-0.5">Review and triage in the incidents queue</div>
                  </div>
                </button>
              )}
              {!agents.loading && agents.online < agents.total && (
                <div className="flex items-start gap-3 px-4 py-3">
                  <div className="w-7 h-7 rounded-xl bg-amber-100 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Users className="w-3.5 h-3.5 text-amber-600" />
                  </div>
                  <div>
                    <div className="text-[10px] font-bold text-gray-800">{agents.total - agents.online} agent{agents.total - agents.online > 1 ? "s" : ""} offline</div>
                    <div className="text-[9px] text-gray-500 mt-0.5">{agents.online}/{agents.total} agents reporting</div>
                  </div>
                </div>
              )}
              {threats.critical === 0 && threats.high === 0 && (agents.loading || agents.online === agents.total) && (
                <div className="flex flex-col items-center gap-2 py-8 px-4 text-center">
                  <div className="w-10 h-10 rounded-2xl bg-emerald-50 border border-emerald-100 flex items-center justify-center">
                    <CheckCircle2 className="w-5 h-5 text-emerald-500" />
                  </div>
                  <p className="text-[10px] font-semibold text-gray-700">All clear</p>
                  <p className="text-[9px] text-gray-400">No critical alerts at this time.</p>
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {/* ── Command palette ───────────────────────────────────────────────── */}
      {cmdOpen && (
        <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 px-4"
          style={{ background: "rgba(0,0,0,0.4)", backdropFilter: "blur(4px)" }}
          onClick={() => setCmdOpen(false)}>
          <div
            className="w-full max-w-lg bg-white rounded-2xl shadow-2xl overflow-hidden border border-gray-200"
            style={{ boxShadow: "0 24px 64px rgba(0,0,0,0.2)" }}
            onClick={e => e.stopPropagation()}
          >
            {/* Search input */}
            <div className="flex items-center gap-3 px-4 py-3.5 border-b border-gray-100">
              <Search className="w-4 h-4 text-gray-400 flex-shrink-0" />
              <input
                ref={cmdInputRef}
                value={cmdQuery}
                onChange={e => { setCmdQuery(e.target.value); setCmdIdx(0); }}
                onKeyDown={handleCmdKey}
                placeholder="Navigate to…"
                className="flex-1 text-[13px] text-gray-800 placeholder-gray-400 bg-transparent focus:outline-none"
              />
              <kbd className="px-2 py-1 rounded-lg text-[9px] font-bold bg-gray-100 text-gray-500 border border-gray-200">ESC</kbd>
            </div>

            {/* Results */}
            <div className="max-h-72 overflow-y-auto py-2">
              {filtered.length === 0 ? (
                <div className="px-4 py-8 text-center text-[11px] text-gray-400">No pages match "{cmdQuery}"</div>
              ) : (
                (() => {
                  let lastGroup = "";
                  return filtered.map((item, i) => {
                    const showGroup = item.group !== lastGroup;
                    lastGroup = item.group;
                    return (
                      <div key={item.path}>
                        {showGroup && (
                          <div className="px-4 py-1 text-[9px] font-bold text-gray-400 uppercase tracking-wider">{item.group}</div>
                        )}
                        <button
                          onClick={() => runCmd(item.path)}
                          onMouseEnter={() => setCmdIdx(i)}
                          className={cn(
                            "w-full flex items-center gap-3 px-4 py-2 text-left transition-colors",
                            i === cmdIdx ? "bg-orange-50" : "hover:bg-gray-50"
                          )}
                        >
                          <LayoutDashboard className={cn("w-3.5 h-3.5 flex-shrink-0", i === cmdIdx ? "text-orange-500" : "text-gray-400")} />
                          <span className={cn("text-[11px] font-medium flex-1", i === cmdIdx ? "text-orange-700" : "text-gray-700")}>{item.label}</span>
                          {i === cmdIdx && <ChevronRight className="w-3 h-3 text-orange-400" />}
                        </button>
                      </div>
                    );
                  });
                })()
              )}
            </div>

            {/* Footer hints */}
            <div className="flex items-center gap-4 px-4 py-2 border-t border-gray-100 bg-gray-50">
              <span className="flex items-center gap-1 text-[9px] text-gray-400">
                <kbd className="px-1.5 py-0.5 rounded bg-white border border-gray-200 text-[8px] font-bold">↑↓</kbd> navigate
              </span>
              <span className="flex items-center gap-1 text-[9px] text-gray-400">
                <kbd className="px-1.5 py-0.5 rounded bg-white border border-gray-200 text-[8px] font-bold">↵</kbd> open
              </span>
              <span className="flex items-center gap-1 text-[9px] text-gray-400">
                <kbd className="px-1.5 py-0.5 rounded bg-white border border-gray-200 text-[8px] font-bold">ESC</kbd> close
              </span>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
