/**
 * RBACContext — Role-based access control for AttackLens dashboard.
 *
 * Roles:
 *   admin    — full access: manage findings, bulk actions, view all agents, key management
 *   analyst  — update findings, add comments, view all data — cannot manage keys/enrollment
 *   viewer   — read-only: cannot perform any write actions
 *
 * In production: role would come from JWT claims decoded at login.
 * For now: persisted in localStorage, selectable from the top header.
 *
 * Usage:
 *   const { role, can } = useRBAC();
 *   if (can("update_finding")) { ... }
 */
import { createContext, useContext, useState, type ReactNode } from "react";

export type Role = "admin" | "analyst" | "viewer";

export interface User {
  name:   string;
  initials: string;
  role:   Role;
  email?: string;
}

// Permissions per action
const PERMISSIONS: Record<string, Role[]> = {
  update_finding:   ["admin", "analyst"],
  bulk_action:      ["admin", "analyst"],
  add_comment:      ["admin", "analyst"],
  close_finding:    ["admin", "analyst"],
  accept_risk:      ["admin", "analyst"],
  mark_fp:          ["admin", "analyst"],
  assign_finding:   ["admin", "analyst"],
  manage_keys:      ["admin"],
  manage_enrollment:["admin"],
  view_findings:    ["admin", "analyst", "viewer"],
  view_raw_data:    ["admin", "analyst", "viewer"],
  export_data:      ["admin"],
};

interface RBACContextValue {
  user:    User;
  setRole: (r: Role) => void;
  can:     (action: string) => boolean;
}

const RBACContext = createContext<RBACContextValue>({
  user:    { name: "Analyst", initials: "AN", role: "analyst" },
  setRole: () => {},
  can:     () => true,
});

const ROLE_DEFAULTS: Record<Role, User> = {
  admin:   { name: "Admin User",   initials: "AU", role: "admin"   },
  analyst: { name: "SOC Analyst",  initials: "SA", role: "analyst" },
  viewer:  { name: "Read-Only",    initials: "RO", role: "viewer"  },
};

function loadRole(): Role {
  try {
    const r = localStorage.getItem("attacklens_role") as Role;
    if (r && ["admin", "analyst", "viewer"].includes(r)) return r;
  } catch { /* ignore */ }
  return "analyst";
}

export function RBACProvider({ children }: { children: ReactNode }) {
  const [role, setRoleState] = useState<Role>(loadRole);

  const setRole = (r: Role) => {
    setRoleState(r);
    try { localStorage.setItem("attacklens_role", r); } catch { /* ignore */ }
  };

  const user = ROLE_DEFAULTS[role];

  const can = (action: string): boolean => {
    const allowed = PERMISSIONS[action];
    if (!allowed) return role === "admin";
    return allowed.includes(role);
  };

  return (
    <RBACContext.Provider value={{ user, setRole, can }}>
      {children}
    </RBACContext.Provider>
  );
}

export function useRBAC() {
  return useContext(RBACContext);
}
