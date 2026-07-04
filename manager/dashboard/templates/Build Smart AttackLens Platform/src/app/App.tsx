import { useState, lazy, Suspense } from "react";
import { ClipboardList, Loader2 } from "lucide-react";
import { Sidebar, type PageId } from "./components/Sidebar";
import { TopHeader } from "./components/TopHeader";
import { ComingSoon } from "./components/ComingSoon";
import { RBACProvider } from "./context/RBACContext";
import { AuthProvider, useAuth } from "./context/AuthContext";
import LoginPage from "./pages/LoginPage";
import { CIS_COMPLIANCE_LIVE } from "./featureFlags";

// Dashboard is the landing page — keep it eager so first paint is instant.
import SecurityDashboard from "./pages/Dashboard";

// Every other page is lazy-loaded: Vite emits one chunk per page, so the
// initial bundle is just the shell + Dashboard instead of all 17 pages. A page
// downloads only when first navigated to (then it's cached).
const ThreatQueue          = lazy(() => import("./pages/ThreatQueue"));
const Incidents            = lazy(() => import("./pages/Incidents"));
const ExecutionThreats     = lazy(() => import("./pages/ExecutionThreats"));
const NetworkThreats       = lazy(() => import("./pages/NetworkThreats"));
const VulnerabilitySurface = lazy(() => import("./pages/VulnerabilitySurface"));
const PersistenceBackdoors = lazy(() => import("./pages/PersistenceBackdoors"));
const IdentityAccess       = lazy(() => import("./pages/IdentityAccess"));
const SecurityPosture      = lazy(() => import("./pages/SecurityPosture"));
const CISCompliance        = CIS_COMPLIANCE_LIVE ? lazy(() => import("./pages/CISCompliance")) : null;
const ThreatIntelligence   = lazy(() => import("./pages/ThreatIntelligence"));
const Timeline             = lazy(() => import("./pages/Timeline"));
const AssetRegistry        = lazy(() => import("./pages/AssetRegistry"));
const DeepAnalysis         = lazy(() => import("./pages/DeepAnalysis"));
const Accuracy             = lazy(() => import("./pages/Accuracy"));
const DetectionCoverage    = lazy(() => import("./pages/DetectionCoverage"));
const Settings             = lazy(() => import("./pages/Settings"));

// ── Router ────────────────────────────────────────────────────────────────────
function PageRouter({ page }: { page: PageId }) {
  switch (page) {
    case "dashboard":        return <SecurityDashboard />;
    case "threat-queue":     return <ThreatQueue />;
    case "incidents":        return <Incidents />;
    case "execution":        return <ExecutionThreats />;
    case "network":          return <NetworkThreats />;
    case "vulnerabilities":  return <VulnerabilitySurface />;
    case "persistence":      return <PersistenceBackdoors />;
    case "identity":         return <IdentityAccess />;
    case "security-posture": return <SecurityPosture />;
    case "compliance":
      return CISCompliance ? <CISCompliance /> : (
        <ComingSoon
          icon={<ClipboardList className="w-6 h-6 text-[--gray-400]" />}
          title="CIS Compliance"
          description="CIS Benchmark compliance scoring for the Posture section is coming soon — this page will track macOS hardening checks against the CIS macOS Benchmark."
        />
      );
    case "threat-intel":     return <ThreatIntelligence />;
    case "timeline":         return <Timeline />;
    case "assets":           return <AssetRegistry />;
    case "raw-data":              return <DeepAnalysis />;
    case "accuracy":              return <Accuracy />;
    case "detection-coverage":    return <DetectionCoverage />;
    case "settings":              return <Settings />;
    default:                 return <SecurityDashboard />;
  }
}

// Lightweight fallback shown while a lazy page chunk downloads.
function PageLoading() {
  return (
    <div className="flex items-center justify-center py-32">
      <div className="flex items-center gap-2 text-gray-400 text-xs font-semibold">
        <span className="w-3.5 h-3.5 border-2 border-gray-200 border-t-orange-400 rounded-full animate-spin" />
        Loading…
      </div>
    </div>
  );
}

// ── Authenticated shell ───────────────────────────────────────────────────────
function AuthenticatedApp() {
  const [activePage, setActivePage] = useState<PageId>("dashboard");

  return (
    <RBACProvider>
      <div className="flex h-screen overflow-hidden" style={{ background: "#F4F6F9" }}>
        <Sidebar activePage={activePage} onNavigate={setActivePage} />

        <div className="flex-1 flex flex-col overflow-hidden min-w-0">
          <TopHeader activePage={activePage} />

          <main
            key={activePage}
            className="flex-1 overflow-y-auto al-page-enter"
            style={{ background: "linear-gradient(160deg,#F7F8FA 0%,#FFFFFF 40%,#F4F6F8 100%)" }}
          >
            <div className="px-6 py-5 max-w-[1280px] mx-auto">
              <Suspense fallback={<PageLoading />}>
                <PageRouter page={activePage} />
              </Suspense>
            </div>
          </main>
        </div>
      </div>
    </RBACProvider>
  );
}

// ── App root — auth gate ──────────────────────────────────────────────────────
function AppInner() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    // Brief check while localStorage hydrates — avoids login flash on refresh
    return (
      <div
        className="min-h-screen flex items-center justify-center"
        style={{ background: "#0a0e1a" }}
      >
        <Loader2 className="w-6 h-6 animate-spin text-orange-500" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginPage onSuccess={() => {/* AuthContext re-renders automatically */}} />;
  }

  return <AuthenticatedApp />;
}

export default function App() {
  return (
    <AuthProvider>
      <AppInner />
    </AuthProvider>
  );
}
