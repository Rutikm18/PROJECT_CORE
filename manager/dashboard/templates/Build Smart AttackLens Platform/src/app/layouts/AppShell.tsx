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

export default function AppShell() {
  const { pathname } = useLocation();

  // key forces page content to remount on route change, matching the old
  // behaviour of `key={activePage}` on <main>.
  return (
    <RefreshProvider>
    <TimeRangeProvider>
      <div className="flex h-screen overflow-hidden" style={{ background: "#F4F6F9" }}>
        <Sidebar />

        <div className="flex-1 flex flex-col overflow-hidden min-w-0">
          <TopHeader />

          <main
            key={pathname}
            className="flex-1 overflow-y-auto al-page-enter"
            style={{ background: "linear-gradient(160deg,#F7F8FA 0%,#FFFFFF 40%,#F4F6F8 100%)" }}
          >
            <div className="px-6 py-5 max-w-[1280px] mx-auto">
              <Outlet />
            </div>
          </main>
        </div>
      </div>
    </TimeRangeProvider>
    </RefreshProvider>
  );
}
