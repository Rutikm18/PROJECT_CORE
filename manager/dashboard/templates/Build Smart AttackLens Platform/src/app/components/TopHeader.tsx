/**
 * TopHeader — Global header with RBAC role selector, breadcrumb, live clock.
 *
 * Role selector lets the user switch between admin / analyst / viewer.
 * In production this would be driven by JWT claims — here it's for demo/testing.
 * Role is persisted in localStorage via RBACContext.
 */
import { useState, useEffect } from "react";
import { Bell, ChevronDown, Shield, Clock } from "lucide-react";
import { useRBAC, type Role } from "../context/RBACContext";
import { type PageId } from "./Sidebar";
import { cn } from "../../lib/utils";

const PAGE_LABELS: Record<PageId, string> = {
  "dashboard":       "Security Dashboard",
  "threat-queue":    "Findings",
  "execution":       "Execution & Malware",
  "network":         "Network Threats",
  "vulnerabilities": "Vulnerability Surface",
  "persistence":     "Persistence & Backdoors",
  "identity":        "Identity & Access",
  "security-posture":"Security Posture",
  "compliance":      "CIS Compliance",
  "threat-intel":    "Threat Intelligence",
  "timeline":        "Timeline & History",
  "assets":          "Asset Registry",
  "raw-data":        "Deep Analysis",
  "accuracy":        "Detection Accuracy",
  "settings":        "Settings",
};

const ROLE_COLORS: Record<Role, string> = {
  admin:   "bg-[--red-50] text-[--red-700] border-[--red-200]",
  analyst: "bg-[--blue-50] text-[--blue-700] border-[--blue-200]",
  viewer:  "bg-[--gray-100] text-[--gray-600] border-[--gray-200]",
};

const ROLE_ICONS: Record<Role, string> = {
  admin:   "🔐",
  analyst: "🔍",
  viewer:  "👁",
};

interface TopHeaderProps {
  activePage?: PageId;
}

export function TopHeader({ activePage }: TopHeaderProps) {
  const { user, setRole } = useRBAC();
  const [roleOpen, setRoleOpen] = useState(false);
  const [time, setTime] = useState(() => new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" }));

  useEffect(() => {
    const t = setInterval(() => {
      setTime(new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" }));
    }, 1000);
    return () => clearInterval(t);
  }, []);

  const pageLabel = activePage ? PAGE_LABELS[activePage] ?? activePage : "Dashboard";

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
      <div className="flex items-center gap-2 text-xs">
        <span className="text-[10px] font-medium" style={{ color: "rgba(0,0,0,0.35)" }}>AttackLens</span>
        <span style={{ color: "rgba(0,0,0,0.2)" }}>›</span>
        <span className="font-semibold text-[11px] text-[--gray-800]">{pageLabel}</span>
      </div>

      {/* Right side controls */}
      <div className="flex items-center gap-3">
        {/* Live clock */}
        <div className="flex items-center gap-1.5 text-[10px] text-[--gray-400] font-mono">
          <Clock className="w-3 h-3" />
          {time}
        </div>

        {/* Live indicator */}
        <div
          className="flex items-center gap-1.5 px-2.5 py-1 rounded-md"
          style={{ background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.2)" }}
        >
          <div className="w-1.5 h-1.5 rounded-full al-dot-breathe" style={{ background: "#10b981" }} />
          <span className="text-[10px] font-semibold" style={{ color: "#059669" }}>Live</span>
        </div>

        {/* RBAC role selector */}
        <div className="relative">
          <button
            onClick={() => setRoleOpen(o => !o)}
            className={cn(
              "flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[10px] font-semibold transition-colors",
              ROLE_COLORS[user.role]
            )}
          >
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
                <button
                  key={r}
                  onClick={() => { setRole(r); setRoleOpen(false); }}
                  className={cn(
                    "w-full flex items-center gap-2 px-3 py-2 text-xs hover:bg-[--gray-50] transition-colors text-left",
                    user.role === r && "bg-[--gray-25] font-semibold"
                  )}
                >
                  <span>{ROLE_ICONS[r]}</span>
                  <div>
                    <div className="font-medium text-[--gray-800] capitalize">{r}</div>
                    <div className="text-[9px] text-[--gray-400]">
                      {r === "admin" ? "Full access + key management" :
                       r === "analyst" ? "Update findings + comments" :
                       "Read-only view"}
                    </div>
                  </div>
                  {user.role === r && <span className="ml-auto text-[--green-600]">✓</span>}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Bell (notifications placeholder) */}
        <div className="relative p-1.5 hover:bg-[--gray-50] rounded-md cursor-pointer transition-colors">
          <Bell className="w-4 h-4 text-[--gray-400]" />
        </div>

        {/* User avatar */}
        <div className={cn(
          "w-7 h-7 rounded-full flex items-center justify-center text-[10px] font-bold text-white cursor-pointer shadow-sm",
          user.role === "admin" ? "bg-gradient-to-br from-[--red-500] to-[--red-700]" :
          user.role === "analyst" ? "bg-gradient-to-br from-[--blue-500] to-[--indigo-600]" :
          "bg-gradient-to-br from-[--gray-400] to-[--gray-600]"
        )}
          title={`${user.name} (${user.role})`}
        >
          {user.initials}
        </div>
      </div>

      {/* Close role dropdown when clicking outside */}
      {roleOpen && (
        <div className="fixed inset-0 z-40" onClick={() => setRoleOpen(false)} />
      )}
    </div>
  );
}
