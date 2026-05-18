import { useState } from "react";
import { Sidebar, type PageId } from "./components/Sidebar";
import { TopHeader } from "./components/TopHeader";
import { RBACProvider } from "./context/RBACContext";

// Pages
import SecurityDashboard    from "./pages/Dashboard";
import ThreatQueue          from "./pages/ThreatQueue";
import ExecutionThreats     from "./pages/ExecutionThreats";
import NetworkThreats       from "./pages/NetworkThreats";
import VulnerabilitySurface from "./pages/VulnerabilitySurface";
import PersistenceBackdoors from "./pages/PersistenceBackdoors";
import IdentityAccess       from "./pages/IdentityAccess";
import SecurityPosture      from "./pages/SecurityPosture";
import CISCompliance        from "./pages/CISCompliance";
import ThreatIntelligence   from "./pages/ThreatIntelligence";
import Timeline             from "./pages/Timeline";
import AssetRegistry        from "./pages/AssetRegistry";
import DeepAnalysis         from "./pages/DeepAnalysis";
import Accuracy             from "./pages/Accuracy";
import Settings             from "./pages/Settings";

// ── Router ────────────────────────────────────────────────────────────────────
function PageRouter({ page }: { page: PageId }) {
  switch (page) {
    case "dashboard":        return <SecurityDashboard />;
    case "threat-queue":     return <ThreatQueue />;
    case "execution":        return <ExecutionThreats />;
    case "network":          return <NetworkThreats />;
    case "vulnerabilities":  return <VulnerabilitySurface />;
    case "persistence":      return <PersistenceBackdoors />;
    case "identity":         return <IdentityAccess />;
    case "security-posture": return <SecurityPosture />;
    case "compliance":       return <CISCompliance />;
    case "threat-intel":     return <ThreatIntelligence />;
    case "timeline":         return <Timeline />;
    case "assets":           return <AssetRegistry />;
    case "raw-data":         return <DeepAnalysis />;
    case "accuracy":         return <Accuracy />;
    case "settings":         return <Settings />;
    default:                 return <SecurityDashboard />;
  }
}

// ── App ───────────────────────────────────────────────────────────────────────
export default function App() {
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
              <PageRouter page={activePage} />
            </div>
          </main>
        </div>
      </div>
    </RBACProvider>
  );
}
