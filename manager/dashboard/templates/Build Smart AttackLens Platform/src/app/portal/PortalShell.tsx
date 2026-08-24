/**
 * PortalShell — the customer chrome.
 *
 * A structural mirror of the operator shell, built from the same tokens and
 * primitives, so the portal reads as the same product rather than a stripped
 * clone. What differs is deliberately small: a limited nav, the customer's own
 * identity, and portal logout.
 *
 * Navigation comes from the server's capability map (/portal/auth/me), never
 * from a client-side role. Hiding a link is presentation; the server refusing
 * the route is the control.
 */
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { Outlet, useLocation, useNavigate } from "react-router";
import { AlertTriangle, LogOut, Menu, RefreshCw } from "lucide-react";
import { PortalSidebar } from "./PortalSidebar";
import { RefreshProvider } from "../context/RefreshContext";
import { TimeRangeProvider } from "../context/TimeRangeContext";
import { PORTAL_LOGIN_PATH, portalApi, type PortalMe } from "./portalClient";

// ── Session context ─────────────────────────────────────────────────────────

interface PortalSession {
  me: PortalMe | null;
  loading: boolean;
  can: (capability: string) => boolean;
  refresh: () => void;
}

const PortalSessionContext = createContext<PortalSession>({
  me: null, loading: true, can: () => false, refresh: () => {},
});

export function usePortalSession() {
  return useContext(PortalSessionContext);
}

export function PortalSessionProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<PortalMe | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let dead = false;
    setLoading(true);
    portalApi<PortalMe>("/auth/me")
      .then(body => { if (!dead) setMe(body); })
      .catch(() => { if (!dead) setMe(null); })
      .finally(() => { if (!dead) setLoading(false); });
    return () => { dead = true; };
  }, [nonce]);

  // Until the server answers, offer nothing. A capability map that defaults to
  // permissive would flash controls the customer may not use.
  const can = (capability: string) => Boolean(me?.capabilities?.[capability]);

  return (
    <PortalSessionContext.Provider
      value={{ me, loading, can, refresh: () => setNonce(n => n + 1) }}>
      {children}
    </PortalSessionContext.Provider>
  );
}

/** Gate for every portal route. Redirects to the portal login, not the operator one. */
export function PortalProtectedRoute({ children }: { children: ReactNode }) {
  const { me, loading } = usePortalSession();
  const navigate = useNavigate();

  useEffect(() => {
    if (!loading && !me) navigate(PORTAL_LOGIN_PATH, { replace: true });
  }, [loading, me, navigate]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32">
        <RefreshCw className="w-4 h-4 animate-spin text-[--gray-300]" />
      </div>
    );
  }
  return me ? <>{children}</> : null;
}

// ── Shell ───────────────────────────────────────────────────────────────────

export function PortalShell() {
  const { me, refresh } = usePortalSession();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [collapsed, setCollapsed] = useState(() => window.innerWidth < 1200);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const adapt = () => {
      setCollapsed(window.innerWidth < 1200);
      if (window.innerWidth >= 768) setMobileOpen(false);
    };
    window.addEventListener("resize", adapt);
    return () => window.removeEventListener("resize", adapt);
  }, []);

  const signOut = async () => {
    try {
      await portalApi("/auth/logout", { method: "POST", redirectOnAuthFailure: false });
    } catch { /* clearing the cookie is best-effort; leaving is what matters */ }
    navigate(PORTAL_LOGIN_PATH, { replace: true });
  };

  const licenceDays = me?.org.license_days_remaining;
  const licenceWarning = typeof licenceDays === "number" && licenceDays <= 30;

  return (
    <RefreshProvider>
      <TimeRangeProvider>
        <div className="flex h-dvh min-h-0 overflow-hidden" style={{ background: "#F4F6F9" }}>
          {mobileOpen && (
            <button
              aria-label="Close navigation"
              onClick={() => setMobileOpen(false)}
              className="fixed inset-0 z-40 bg-black/45 md:hidden"
            />
          )}

          <PortalSidebar
            capabilities={me?.capabilities}
            orgName={me?.org.name ?? "Security Portal"}
            collapsed={collapsed}
            mobileOpen={mobileOpen}
            onNavigate={() => setMobileOpen(false)}
          />

          <div className="flex-1 flex flex-col overflow-hidden min-w-0">
            <header className="bg-white border-b border-[--gray-200] flex-shrink-0">
              <div className="h-[3px]" style={{ background: "linear-gradient(90deg,#7C3AED,#8B5CF6,#A78BFA)" }} />
              <div className="px-4 py-2.5 flex items-center gap-3 flex-wrap">
                <button
                  onClick={() => (window.innerWidth < 768
                    ? setMobileOpen(v => !v)
                    : setCollapsed(v => !v))}
                  className="p-1.5 rounded-lg text-[--gray-400] hover:text-[--gray-700] hover:bg-[--gray-100] transition-colors"
                  aria-label="Toggle navigation">
                  <Menu className="w-4 h-4" />
                </button>
                <div className="min-w-0">
                  <div className="text-[12px] font-bold text-[--gray-900] truncate">
                    {me?.org.name ?? "Security Portal"}
                  </div>
                  <div className="text-[9px] text-[--gray-400]">
                    {me?.agent_count ?? 0} endpoint{me?.agent_count === 1 ? "" : "s"} &middot; read-only
                  </div>
                </div>

                <div className="flex items-center gap-2 ml-auto flex-shrink-0">
                  <button
                    onClick={refresh}
                    className="flex items-center gap-1.5 px-2.5 py-1.5 bg-white border border-[--gray-200] text-[--gray-500] text-[11px] font-bold rounded-xl hover:border-purple-300 hover:text-purple-700 transition-colors"
                    aria-label="Refresh">
                    <RefreshCw className="w-3.5 h-3.5" />
                  </button>
                  <span className="text-[11px] text-[--gray-600] hidden sm:block truncate max-w-[200px]">
                    {me?.email}
                  </span>
                  <button
                    onClick={() => void signOut()}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-[--gray-200] text-[--gray-600] text-[11px] font-bold rounded-xl hover:border-red-300 hover:text-red-600 transition-colors">
                    <LogOut className="w-3.5 h-3.5" />Sign out
                  </button>
                </div>
              </div>

              {licenceWarning && (
                <div className="flex items-center gap-2 px-4 py-2 bg-amber-50 border-t border-amber-200">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-600 flex-shrink-0" />
                  <span className="text-[10px] text-amber-900 font-semibold">
                    Your licence expires in {licenceDays} day{licenceDays === 1 ? "" : "s"} &mdash;
                    contact your security provider to renew.
                  </span>
                </div>
              )}
            </header>

            <main
              key={pathname}
              className="flex-1 overflow-y-auto al-page-enter"
              style={{ background: "linear-gradient(160deg,#F7F8FA 0%,#FFFFFF 40%,#F4F6F8 100%)" }}>
              <div className="px-3 py-4 sm:px-4 lg:px-6 lg:py-5 max-w-[1600px] mx-auto">
                <Outlet />
              </div>
            </main>
          </div>
        </div>
      </TimeRangeProvider>
    </RefreshProvider>
  );
}
