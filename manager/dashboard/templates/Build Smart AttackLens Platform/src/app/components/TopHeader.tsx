/**
 * TopHeader — global header strip.
 *
 * Breadcrumb is derived from the current URL (useLocation) so no prop
 * drilling is needed.  The live clock, RBAC role selector, and logout
 * button are unchanged from the previous implementation.
 */
import { useState, useEffect } from "react";
import { useLocation } from "react-router";
import { Bell, ChevronDown, Shield, Clock, LogOut } from "lucide-react";
import { useRBAC, type Role } from "../context/RBACContext";
import { useAuth } from "../context/AuthContext";
import { cn } from "../../lib/utils";

// ── Breadcrumb map (pathname segment → human label) ───────────────────────────

const SEGMENT_LABELS: Record<string, string> = {
  dashboard:    "Security Dashboard",
  findings:     "Validated Findings",
  incidents:    "All Incidents",
  terrain:      "Attack Terrain",
  origin:       "Origin",
  vector:       "Vector",
  citadels:     "Citadels",
  persistence:  "Persistence & Backdoors",
  identity:     "Identity & Access",
  posture:      "Posture",
  overview:     "Security Posture",
  compliance:   "CIS Compliance",
  intelligence: "Threat Intelligence",
  ioc:          "IOC Triage",
  cve:          "CVE Intel",
  kev:          "KEV Mandates",
  hunt:         "Hunt Queries",
  feeds:        "Feed Status",
  assets:       "Asset Registry",
  timeline:     "Timeline & History",
  analysis:     "Analysis",
  deep:         "Deep Analysis",
  accuracy:     "Detection Accuracy",
  coverage:     "Detection Coverage",
  settings:     "Settings",
  org:          "Organisation",
  license:      "License",
  roles:        "Roles",
  platform:     "Platform",
  validation:   "Validation",
  retention:    "Data Retention",
  ai:           "AI Configuration",
  notifications:"Notifications",
  integrations: "Integrations",
  login:        "Sign In",
};

function pathToBreadcrumbs(pathname: string): string[] {
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length === 0) return ["Security Dashboard"];
  return parts.map(p => SEGMENT_LABELS[p] ?? p);
}

// ── Component ─────────────────────────────────────────────────────────────────

const ROLE_COLORS: Record<Role, string> = {
  admin:   "bg-[--red-50] text-[--red-700] border-[--red-200]",
  analyst: "bg-[--blue-50] text-[--blue-700] border-[--blue-200]",
  viewer:  "bg-[--gray-100] text-[--gray-600] border-[--gray-200]",
};
const ROLE_ICONS: Record<Role, string> = { admin: "🔐", analyst: "🔍", viewer: "👁" };

interface TopHeaderProps {
  // activePage prop kept for backward-compat; URL takes precedence when present.
  activePage?: string;
}

export function TopHeader({ activePage: _activePage }: TopHeaderProps) {
  const { user, setRole } = useRBAC();
  const { logout, user: authUser } = useAuth();
  const location = useLocation();
  const [roleOpen, setRoleOpen] = useState(false);
  const [time, setTime] = useState(() =>
    new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" })
  );

  useEffect(() => {
    const t = setInterval(() => {
      setTime(new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" }));
    }, 1000);
    return () => clearInterval(t);
  }, []);

  const crumbs = pathToBreadcrumbs(location.pathname);
  const pageLabel = crumbs[crumbs.length - 1] ?? "Dashboard";

  return (
    <div
      className="h-11 flex items-center justify-between px-5 flex-shrink-0 relative"
      style={{
        background: "rgba(255,255,255,0.96)",
        borderBottom: "1px solid rgba(0,0,0,0.07)",
        boxShadow: "0 1px 8px rgba(0,0,0,0.05)",
        backdropFilter: "blur(12px)",
      }}
    >
      {/* Breadcrumb */}
      <div className="flex items-center gap-1.5 text-xs">
        <span className="text-[10px] font-medium" style={{ color: "rgba(0,0,0,0.35)" }}>AttackLens</span>
        {crumbs.map((crumb, i) => (
          <span key={i} className="flex items-center gap-1.5">
            <span style={{ color: "rgba(0,0,0,0.2)" }}>›</span>
            <span className={cn(
              i === crumbs.length - 1
                ? "font-semibold text-[11px] text-[--gray-800]"
                : "text-[10px] text-[--gray-500]"
            )}>
              {crumb}
            </span>
          </span>
        ))}
      </div>

      {/* Right side */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5 text-[10px] text-[--gray-400] font-mono">
          <Clock className="w-3 h-3" />
          {time}
        </div>

        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md"
          style={{ background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.2)" }}>
          <div className="w-1.5 h-1.5 rounded-full al-dot-breathe" style={{ background: "#10b981" }} />
          <span className="text-[10px] font-semibold" style={{ color: "#059669" }}>Live</span>
        </div>

        {/* RBAC role selector */}
        <div className="relative">
          <button onClick={() => setRoleOpen(o => !o)}
            className={cn("flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[10px] font-semibold transition-colors", ROLE_COLORS[user.role])}>
            <Shield className="w-3 h-3" />
            <span>{ROLE_ICONS[user.role]} {user.role.toUpperCase()}</span>
            <ChevronDown className="w-3 h-3 opacity-60" />
          </button>
          {roleOpen && (
            <div className="absolute right-0 top-full mt-1 bg-white border border-[--gray-200] rounded-lg shadow-lg z-50 w-44 py-1">
              <div className="px-3 py-1.5 text-[9px] font-bold text-[--gray-400] uppercase tracking-wide border-b border-[--gray-100]">
                Switch Role
              </div>
              {(["admin", "analyst", "viewer"] as Role[]).map(r => (
                <button key={r} onClick={() => { setRole(r); setRoleOpen(false); }}
                  className={cn("w-full flex items-center gap-2 px-3 py-2 text-xs hover:bg-[--gray-50] transition-colors text-left",
                    user.role === r && "bg-[--gray-25] font-semibold")}>
                  <span>{ROLE_ICONS[r]}</span>
                  <div>
                    <div className="font-medium text-[--gray-800] capitalize">{r}</div>
                    <div className="text-[9px] text-[--gray-400]">
                      {r === "admin" ? "Full access + key management" :
                       r === "analyst" ? "Update findings + comments" : "Read-only view"}
                    </div>
                  </div>
                  {user.role === r && <span className="ml-auto text-[--green-600]">✓</span>}
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="relative p-1.5 hover:bg-[--gray-50] rounded-md cursor-pointer transition-colors">
          <Bell className="w-4 h-4 text-[--gray-400]" />
        </div>

        <div className={cn(
          "w-7 h-7 rounded-full flex items-center justify-center text-[10px] font-bold text-white cursor-pointer shadow-sm",
          user.role === "admin"   ? "bg-gradient-to-br from-[--red-500] to-[--red-700]" :
          user.role === "analyst" ? "bg-gradient-to-br from-[--blue-500] to-[--indigo-600]" :
          "bg-gradient-to-br from-[--gray-400] to-[--gray-600]"
        )} title={`${authUser?.email ?? user.name} (${user.role})`}>
          {user.initials}
        </div>

        <button onClick={() => logout()} className="p-1.5 hover:bg-[--gray-50] rounded-md cursor-pointer transition-colors"
          title="Sign out" aria-label="Sign out">
          <LogOut className="w-3.5 h-3.5 text-[--gray-400]" />
        </button>
      </div>

      {roleOpen && <div className="fixed inset-0 z-40" onClick={() => setRoleOpen(false)} />}
    </div>
  );
}
