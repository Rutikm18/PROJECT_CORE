/**
 * RBACContext — role-based UI affordances for the AttackLens dashboard.
 *
 * Roles:
 *   admin    — full access: manage findings, bulk actions, key management
 *   analyst  — update findings, add comments, view all data
 *   viewer   — read-only
 *
 * WHERE THE ROLE COMES FROM
 * The role is read from GET /api/v1/auth/me, which returns the claim carried by
 * the signed session token. It was previously read from
 * `localStorage.getItem("attacklens_role")` and set by a "Switch Role" menu —
 * a value any viewer could change to "admin" in devtools. That was harmless
 * only for as long as nothing depended on it; with the API now enforcing
 * authorization server-side, a client-side role would have been actively
 * misleading, showing controls the server refuses.
 *
 * WHAT THIS IS AND IS NOT
 * `can()` decides what the UI *offers*. It is not a security boundary and must
 * never be the only thing standing between a user and an action — the server
 * decides that. Hiding a button is presentation; the 403 is the control.
 *
 * Until the role resolves, `can()` returns false. An unauthenticated or
 * still-loading session gets the least privilege, not the most.
 *
 * Usage:
 *   const { role, can } = useRBAC();
 *   if (can("update_finding")) { ... }
 */
import {
  createContext, useCallback, useContext, useEffect, useState, type ReactNode,
} from "react";

export type Role = "admin" | "analyst" | "viewer";

export const ROLES: Role[] = ["admin", "analyst", "viewer"];

export interface User {
  name:     string;
  initials: string;
  role:     Role;
  email?:   string;
}

// Permissions per action.
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

/** Least-privilege placeholder used before /auth/me answers. */
const ANONYMOUS: User = { name: "Signing in", initials: "?", role: "viewer" };

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as string[]).includes(value);
}

/**
 * Build the display user from an /auth/me payload, falling back to the least
 * privilege whenever the server did not give a role we recognise. Exported so
 * the mapping is testable without mounting the provider.
 */
export function userFromAuthMe(payload: unknown): User {
  if (!payload || typeof payload !== "object") return ANONYMOUS;
  const body = payload as Record<string, unknown>;
  const role: Role = isRole(body.role) ? body.role : "viewer";
  const email = typeof body.email === "string" ? body.email : undefined;
  const name = typeof body.name === "string" && body.name.trim()
    ? body.name.trim()
    : (email?.split("@")[0] ?? role);
  const initials = typeof body.initials === "string" && body.initials.trim()
    ? body.initials.trim().slice(0, 2).toUpperCase()
    : name.slice(0, 1).toUpperCase();
  return { name, initials, role, email };
}

export function permitted(role: Role | null, action: string): boolean {
  if (role === null) return false;          // unresolved session -> offer nothing
  const allowed = PERMISSIONS[action];
  if (!allowed) return role === "admin";    // unknown action -> admin only
  return allowed.includes(role);
}

interface RBACContextValue {
  user:    User;
  role:    Role | null;      // null while /auth/me is in flight
  loading: boolean;
  can:     (action: string) => boolean;
  refresh: () => void;
}

const RBACContext = createContext<RBACContextValue>({
  user:    ANONYMOUS,
  role:    null,
  loading: true,
  can:     () => false,
  refresh: () => {},
});

export function RBACProvider({ children }: { children: ReactNode }) {
  const [user,    setUser]    = useState<User>(ANONYMOUS);
  const [role,    setRole]    = useState<Role | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce,   setNonce]   = useState(0);

  const refresh = useCallback(() => setNonce(n => n + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    void fetch("/api/v1/auth/me", {
      credentials: "include",
      signal: controller.signal,
    })
      .then(r => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then(body => {
        const resolved = userFromAuthMe(body);
        setUser(resolved);
        setRole(resolved.role);
      })
      .catch(() => {
        // Not signed in, or the session expired. Stay at least privilege —
        // ProtectedRoute handles the redirect to /login.
        setUser(ANONYMOUS);
        setRole(null);
      })
      .finally(() => setLoading(false));
    return () => controller.abort();
  }, [nonce]);

  const can = useCallback(
    (action: string) => permitted(role, action),
    [role],
  );

  return (
    <RBACContext.Provider value={{ user, role, loading, can, refresh }}>
      {children}
    </RBACContext.Provider>
  );
}

export function useRBAC() {
  return useContext(RBACContext);
}
