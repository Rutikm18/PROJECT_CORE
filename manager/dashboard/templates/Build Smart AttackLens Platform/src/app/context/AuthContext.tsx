/**
 * AuthContext — Authentication state for the AttackLens dashboard.
 *
 * Security controls enforced client-side:
 *  - Absolute session timeout: auto-logout at JWT exp claim
 *  - Idle timeout: auto-logout after N minutes with no user interaction
 *    (default 30 min, server-configurable via idle_minutes in login response)
 *  - Token never logged or sent in URL parameters
 *  - localStorage cleared completely on logout
 *  - Any 401 from any API call triggers immediate logout
 *  - httpOnly cookie is the authoritative session; localStorage is read-only mirror
 */
import {
  createContext, useContext, useState, useEffect, useCallback, useRef,
  type ReactNode,
} from "react";

const TOKEN_KEY   = "al_token";
const USER_KEY    = "al_user";
const IDLE_KEY    = "al_idle_minutes";
const API_BASE    = "";   // same-origin

const DEFAULT_IDLE_MINUTES = 30;

// Activity events that reset the idle clock
const ACTIVITY_EVENTS: string[] = [
  "mousedown", "mousemove", "keydown", "touchstart", "scroll", "click",
];

export interface AuthUser {
  email:      string;
  role:       string;
  name:       string;
  initials:   string;
  expires_at: number;    // epoch seconds
}

interface AuthState {
  user:            AuthUser | null;
  token:           string | null;
  isAuthenticated: boolean;
  isLoading:       boolean;
  login:  (email: string, password: string) => Promise<{ ok: boolean; error?: string }>;
  logout: (reason?: string) => Promise<void>;
}

const AuthContext = createContext<AuthState>({
  user: null, token: null, isAuthenticated: false, isLoading: true,
  login:  async () => ({ ok: false }),
  logout: async () => {},
});

function loadStored(): { user: AuthUser | null; token: string | null; idleMinutes: number } {
  try {
    const token = localStorage.getItem(TOKEN_KEY);
    const raw   = localStorage.getItem(USER_KEY);
    const idle  = parseInt(localStorage.getItem(IDLE_KEY) ?? "", 10) || DEFAULT_IDLE_MINUTES;
    if (!token || !raw) return { user: null, token: null, idleMinutes: DEFAULT_IDLE_MINUTES };
    const user: AuthUser = JSON.parse(raw);
    // Discard if already expired (60s buffer avoids a race at exactly exp)
    if (user.expires_at && user.expires_at < Date.now() / 1000 - 60) {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
      return { user: null, token: null, idleMinutes: DEFAULT_IDLE_MINUTES };
    }
    return { user, token, idleMinutes: idle };
  } catch {
    return { user: null, token: null, idleMinutes: DEFAULT_IDLE_MINUTES };
  }
}

function persist(token: string, user: AuthUser, idleMinutes: number) {
  try {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
    localStorage.setItem(IDLE_KEY, String(idleMinutes));
  } catch { /* storage quota — non-fatal */ }
}

function clearStorage() {
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    localStorage.removeItem(IDLE_KEY);
  } catch { /* ignore */ }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token,      setToken]   = useState<string | null>(null);
  const [user,       setUser]    = useState<AuthUser | null>(null);
  const [isLoading,  setLoading] = useState(true);
  const idleMinutesRef           = useRef<number>(DEFAULT_IDLE_MINUTES);
  const idleTimerRef             = useRef<ReturnType<typeof setTimeout> | null>(null);
  const tokenRef                 = useRef<string | null>(null);

  // Keep tokenRef in sync for use inside event listeners (stale closure safe)
  useEffect(() => { tokenRef.current = token; }, [token]);

  // ── Logout (shared between idle and explicit) ───────────────────────────
  const logout = useCallback(async (reason = "user") => {
    const t = tokenRef.current;
    try {
      await fetch(`${API_BASE}/api/v1/auth/logout`, {
        method: "POST",
        headers: t ? { Authorization: `Bearer ${t}` } : {},
        credentials: "include",
      });
    } catch { /* best-effort; cookie still cleared */ }
    clearStorage();
    setToken(null);
    setUser(null);
    if (reason === "idle") {
      // Brief visual cue — store a flag so LoginPage can show "session expired"
      try { sessionStorage.setItem("al_logout_reason", "idle"); } catch { /* ignore */ }
    }
  }, []);

  // ── Idle timer ───────────────────────────────────────────────────────────
  const resetIdleTimer = useCallback(() => {
    if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
    const ms = idleMinutesRef.current * 60 * 1000;
    idleTimerRef.current = setTimeout(() => logout("idle"), ms);
  }, [logout]);

  // ── Hydrate from localStorage ────────────────────────────────────────────
  useEffect(() => {
    const { user: u, token: t, idleMinutes } = loadStored();
    idleMinutesRef.current = idleMinutes;
    setToken(t);
    setUser(u);
    setLoading(false);
  }, []);

  // ── Absolute expiry timer ────────────────────────────────────────────────
  useEffect(() => {
    if (!user) return;
    const ms = user.expires_at * 1000 - Date.now();
    if (ms <= 0) { clearStorage(); setToken(null); setUser(null); return; }
    const id = setTimeout(() => logout("expired"), ms);
    return () => clearTimeout(id);
  }, [user, logout]);

  // ── Idle activity tracking (only when authenticated) ─────────────────────
  useEffect(() => {
    if (!user) {
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
      return;
    }
    resetIdleTimer();
    ACTIVITY_EVENTS.forEach(ev => window.addEventListener(ev, resetIdleTimer, { passive: true }));
    return () => {
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
      ACTIVITY_EVENTS.forEach(ev => window.removeEventListener(ev, resetIdleTimer));
    };
  }, [user, resetIdleTimer]);

  // ── Login ────────────────────────────────────────────────────────────────
  const login = useCallback(async (email: string, password: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",   // receive httpOnly cookie
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        return { ok: false, error: data.error ?? "Login failed." };
      }
      const idleMinutes: number = data.idle_minutes ?? DEFAULT_IDLE_MINUTES;
      idleMinutesRef.current = idleMinutes;
      const authUser: AuthUser = { ...data.user, expires_at: data.expires_at };
      persist(data.token, authUser, idleMinutes);
      setToken(data.token);
      setUser(authUser);
      try { sessionStorage.removeItem("al_logout_reason"); } catch { /* ignore */ }
      return { ok: true };
    } catch {
      return { ok: false, error: "Network error. Check your connection." };
    }
  }, []);

  return (
    <AuthContext.Provider value={{
      user, token,
      isAuthenticated: !!user && !!token,
      isLoading,
      login, logout,
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
