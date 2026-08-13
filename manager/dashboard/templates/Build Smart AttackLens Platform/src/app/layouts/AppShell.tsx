/**
 * AppShell — authenticated layout wrapper.
 *
 * Renders:  Sidebar  |  TopHeader  (above)
 *                    |  <Outlet /> (below — the active page)
 *
 * React Router renders child routes into <Outlet />, so page components
 * never need to know they live inside a shell.
 */
import { Outlet, useLocation } from "react-router";
import { Sidebar } from "../components/Sidebar";
import { TopHeader } from "../components/TopHeader";
import { TimeRangeProvider } from "../context/TimeRangeContext";
import { RefreshProvider } from "../context/RefreshContext";
import { useCallback, useEffect, useState } from "react";
import {
  BRIGHTNESS_STORAGE_KEY,
  brightnessOverlay,
  normalizeBrightness,
} from "../lib/brightness";

export type NavigationMode = "mobile" | "rail" | "expanded";

export function navigationModeForWidth(width: number, prefersCollapsed = false): NavigationMode {
  if (width < 768) return "mobile";
  if (width < 1200 || prefersCollapsed) return "rail";
  return "expanded";
}

export default function AppShell() {
  const { pathname } = useLocation();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    return navigationModeForWidth(
      window.innerWidth,
      localStorage.getItem("attacklens.sidebarCollapsed") === "true",
    ) === "rail";
  });
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false);
  const [brightness, setBrightness] = useState(() => (
    normalizeBrightness(localStorage.getItem(BRIGHTNESS_STORAGE_KEY))
  ));

  const updateBrightness = useCallback((value: number) => {
    const next = normalizeBrightness(value);
    setBrightness(next);
    localStorage.setItem(BRIGHTNESS_STORAGE_KEY, String(next));
  }, []);

  useEffect(() => {
    const adapt = () => {
      const preferred = localStorage.getItem("attacklens.sidebarCollapsed") === "true";
      const mode = navigationModeForWidth(window.innerWidth, preferred);
      if (mode === "mobile") {
        setSidebarCollapsed(false);
        setMobileNavigationOpen(false);
      } else if (mode === "rail") {
        setSidebarCollapsed(true);
        setMobileNavigationOpen(false);
      } else {
        setSidebarCollapsed(false);
        setMobileNavigationOpen(false);
      }
    };
    window.addEventListener("resize", adapt);
    return () => window.removeEventListener("resize", adapt);
  }, []);

  const toggleSidebar = useCallback(() => {
    if (window.innerWidth < 768) {
      setMobileNavigationOpen(value => !value);
      return;
    }
    setSidebarCollapsed(value => {
      const next = !value;
      localStorage.setItem("attacklens.sidebarCollapsed", String(next));
      return next;
    });
  }, []);

  useEffect(() => {
    const onShortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "b") {
        event.preventDefault();
        toggleSidebar();
      }
    };
    window.addEventListener("keydown", onShortcut);
    return () => window.removeEventListener("keydown", onShortcut);
  }, [toggleSidebar]);

  // key forces page content to remount on route change, matching the old
  // behaviour of `key={activePage}` on <main>.
  const overlay = brightnessOverlay(brightness);

  return (
    <RefreshProvider>
    <TimeRangeProvider>
      <div className="flex h-dvh min-h-0 overflow-hidden" style={{ background: "#F4F6F9" }}>
        {mobileNavigationOpen && (
          <button
            aria-label="Close navigation"
            onClick={() => setMobileNavigationOpen(false)}
            className="fixed inset-0 z-40 bg-black/45 md:hidden"
          />
        )}
        <Sidebar
          collapsed={sidebarCollapsed}
          mobileOpen={mobileNavigationOpen}
          onToggle={toggleSidebar}
          onNavigate={() => setMobileNavigationOpen(false)}
        />

        <div className="flex-1 flex flex-col overflow-hidden min-w-0">
          <TopHeader
            brightness={brightness}
            onBrightnessChange={updateBrightness}
            onOpenNavigation={() => setMobileNavigationOpen(true)}
          />

          <main
            key={pathname}
            className="flex-1 overflow-y-auto al-page-enter"
            style={{ background: "linear-gradient(160deg,#F7F8FA 0%,#FFFFFF 40%,#F4F6F8 100%)" }}
          >
            <div className="px-3 py-4 sm:px-4 lg:px-6 lg:py-5 max-w-[1600px] mx-auto">
              <Outlet />
            </div>
          </main>
        </div>
        <div
          aria-hidden="true"
          data-app-brightness={brightness}
          className="fixed inset-0 z-[9999] pointer-events-none transition-opacity duration-150"
          style={overlay}
        />
      </div>
    </TimeRangeProvider>
    </RefreshProvider>
  );
}
