import { useState } from "react";
import { Sidebar, type PageId } from "./components/Sidebar";
import { TopHeader } from "./components/TopHeader";

// Pages
import ThreatQueue          from "./pages/ThreatQueue";
import ExecutionThreats     from "./pages/ExecutionThreats";
import NetworkThreats       from "./pages/NetworkThreats";
import VulnerabilitySurface from "./pages/VulnerabilitySurface";
import PersistenceBackdoors from "./pages/PersistenceBackdoors";
import IdentityAccess       from "./pages/IdentityAccess";
import SecurityPosture      from "./pages/SecurityPosture";
import AttackChains         from "./pages/AttackChains";
import ThreatIntelligence   from "./pages/ThreatIntelligence";
import AIAnalyst            from "./pages/AIAnalyst";
import Timeline             from "./pages/Timeline";
import AssetRegistry        from "./pages/AssetRegistry";

// Legacy pages (keep as-is for now)
import { CTEMPipeline }  from "./components/CTEMPipeline";
import { KPICard }       from "./components/KPICard";
import { Panel, PanelHeader, PanelBody } from "./components/Panel";
import { CISCard }       from "./components/CISCard";
import { DomainHealthRow } from "./components/DomainHealthRow";
import { SeverityBadge } from "./components/SeverityBadge";
import { IntelBadge }    from "./components/IntelBadge";

// ── Command Center (Home) ─────────────────────────────────────────────────────
function CommandCenter() {
  return (
    <div className="space-y-4">
      {/* Backstory banner */}
      <div className="bg-gradient-to-r from-[--brand-orange-50] to-white border border-[--gray-200] rounded-lg shadow-card border-l-4 border-l-[--brand-orange] p-4">
        <div className="flex items-start gap-3">
          <div className="w-8 h-8 bg-gradient-orange rounded-lg flex items-center justify-center flex-shrink-0">
            <span className="text-white font-bold text-sm">⌘</span>
          </div>
          <div>
            <h1 className="text-base font-bold text-[--gray-900] mb-0.5">Command Center</h1>
            <p className="text-xs text-[--gray-500] mb-1.5">Real-time SOC overview · risk posture · shift summary</p>
            <p className="text-xs text-[--gray-600] leading-relaxed max-w-3xl">
              Every SOC shift starts here. This screen answers the single question every analyst asks when they sit down: "What's on fire?" The composite risk score aggregates CVSS × EPSS × KEV × asset tier into a single 0–10 number. The CTEM pipeline shows where threats sit in the detect→contain→remediate lifecycle. Use the left panel to drill into any specific domain.
            </p>
          </div>
        </div>
      </div>

      <CTEMPipeline />

      <div className="grid grid-cols-5 gap-3">
        <KPICard label="Risk Score" value="8.7" meta={<><span className="text-[--gray-500]">/ 10 ·</span><SeverityBadge severity="CRITICAL" /></>} delta={{ value: "+0.4", trend: "down" }} />
        <KPICard label="Exposure Score" value="74" meta={<><span>KEV: 2 · EPSS avg: 61%</span></>} delta={{ value: "+12", trend: "down" }} />
        <KPICard label="Critical Findings" value="7" meta={<><SeverityBadge severity="CRITICAL" /><span>· 3 new</span></>} delta={{ value: "+3", trend: "down" }} />
        <KPICard label="CIS Pass Rate" value="34%" valueColor="text-[--amber-600]" meta={<><span>18 / 53 controls</span></>} delta={{ value: "-8%", trend: "down" }} />
        <KPICard label="Remediated 30d" value="18" meta={<><span className="text-[--green-600]">●</span><span>MTTR 6.2h</span></>} delta={{ value: "+3", trend: "up" }} />
      </div>

      <div className="grid grid-cols-[1fr_320px] gap-4">
        <div className="space-y-4">
          <Panel>
            <PanelHeader title="CIS Benchmark Compliance" meta="macOS v8 · 53 controls" action={<a href="#" className="text-xs text-[--brand-orange-700] hover:text-[--brand-orange] font-semibold transition-colors">Full Report →</a>} />
            <PanelBody>
              <div className="grid grid-cols-2 gap-3 mb-4">
                <CISCard controlId="CIS-1" percentage={60} title="Asset Inventory"       failDetails="hardware · software · sbom · 4 fail" />
                <CISCard controlId="CIS-2" percentage={45} title="Software Asset Mgmt"   failDetails="apps · packages · binaries · 6 fail" />
                <CISCard controlId="CIS-4" percentage={12} title="Secure Configuration"  failDetails="SIP off · GK off · FV off · 9 fail" />
                <CISCard controlId="CIS-5" percentage={25} title="Account Management"    failDetails="UID-0 non-root account · 3 fail" />
                <CISCard controlId="CIS-7" percentage={20} title="Vulnerability Mgmt"    failDetails="8 unpatched CVEs · 7 fail" />
                <CISCard controlId="CIS-12" percentage={50} title="Network Infrastructure" failDetails="ports · connections · arp · 5 fail" />
              </div>
              <div className="flex items-center gap-3 pt-3 border-t border-[--gray-200]">
                <span className="text-[11px] font-medium text-[--gray-500] uppercase tracking-wide">Overall CIS Score</span>
                <div className="flex-1 h-2 bg-[--gray-100] rounded-full shadow-inner">
                  <div className="h-full bg-gradient-to-r from-[--red-500] to-[--red-600] rounded-full shadow-sm" style={{ width: "34%" }} />
                </div>
                <span className="text-[11px] font-bold text-[--red-600]">34% · FAILING</span>
              </div>
            </PanelBody>
          </Panel>

          <Panel>
            <PanelHeader title="Security Domain Health" meta="6 domains · 21 sections" />
            <PanelBody className="py-0">
              <DomainHealthRow domain="Security Controls"  score={9.4} criticalCount={2} highCount={1} sections={["security", "sysctl"]} />
              <DomainHealthRow domain="Network Exposure"   score={9.1} criticalCount={3} highCount={4} sections={["connections", "ports", "network"]} />
              <DomainHealthRow domain="Persistence & Exec" score={8.4} criticalCount={1} highCount={5} sections={["processes", "services", "tasks"]} />
              <DomainHealthRow domain="Vuln Surface"       score={7.3} criticalCount={1} highCount={3} sections={["packages", "apps"]} />
              <DomainHealthRow domain="Identity & Access"  score={6.2} criticalCount={2} highCount={3} sections={["users", "services"]} />
              <DomainHealthRow domain="Behavioral"         score={4.1} criticalCount={0} highCount={2} sections={["metrics", "agent_health"]} />
            </PanelBody>
          </Panel>
        </div>

        <div className="space-y-4">
          <Panel>
            <PanelHeader title="Exposure Score" />
            <PanelBody>
              <div className="text-center mb-4 p-4 bg-gradient-to-br from-[--red-50] to-white rounded-lg border border-[--red-600]/20">
                <div className="text-5xl font-bold bg-gradient-to-r from-[--red-600] to-[--red-700] bg-clip-text text-transparent mb-2">8.7</div>
                <div className="text-xs text-[--gray-500] flex items-center justify-center gap-2">
                  <span className="font-medium">out of 10 ·</span><SeverityBadge severity="CRITICAL" />
                </div>
              </div>
              <div className="border-t border-[--gray-200] pt-3 space-y-2.5">
                {[["CVSS base","9.1","text-[--red-600]"],["EPSS top CVE","94%","text-[--red-600]"],["KEV matches","2","text-[--amber-600]"],["CIS pass rate","34%","text-[--amber-600]"]].map(([l,v,c]) => (
                  <div key={l} className="flex items-center justify-between text-xs p-2 hover:bg-[--gray-50] rounded-lg">
                    <span className="font-medium text-[--gray-600]">{l}</span>
                    <span className={`font-bold ${c}`}>{v}</span>
                  </div>
                ))}
                <div className="flex items-center justify-between text-xs p-2 hover:bg-[--gray-50] rounded-lg">
                  <span className="font-medium text-[--gray-600]">SLA status</span>
                  <span className="px-2 py-1 bg-gradient-to-r from-[--red-50] to-[--red-100] text-[--red-600] text-[10px] font-bold rounded-md border border-[--red-600]/20">BREACHED</span>
                </div>
              </div>
            </PanelBody>
          </Panel>

          <Panel>
            <PanelHeader title="Threat Intel Feeds" meta={<div className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-[--green-600]" /><span>All feeds active</span></div>} />
            <PanelBody className="space-y-2">
              {[
                ["CISA KEV",  2, 100,"red",  "1h ago"],
                ["NVD/EPSS",  8,  90,"blue", "live"  ],
                ["Feodo C2",  1,  20,"red",  "1h ago"],
                ["ET Rules",  3,  60,"gray", "1h ago"],
                ["ThreatFox", 2,  75,"blue", "30m ago"],
              ].map(([src, cnt, pct, col, upd]) => (
                <div key={src as string} className="flex items-center gap-2 text-xs p-2 hover:bg-[--gray-50] rounded-lg">
                  <div className="w-20 font-semibold text-[--gray-700]">{src}</div>
                  <div className="w-8 font-bold text-[--gray-900] text-right">{cnt}</div>
                  <div className="flex-1 h-1.5 bg-[--gray-100] rounded-full">
                    <div className={`h-full rounded-full ${col === "red" ? "bg-gradient-to-r from-[--red-500] to-[--red-600]" : col === "blue" ? "bg-gradient-to-r from-[--blue-500] to-[--blue-600]" : "bg-[--gray-400]"}`}
                      style={{ width: `${pct}%` }} />
                  </div>
                  <div className="w-2 h-2 rounded-full bg-[--green-600] animate-pulse" />
                  <div className="text-[--gray-500]">{upd}</div>
                </div>
              ))}
            </PanelBody>
          </Panel>
        </div>
      </div>
    </div>
  );
}

// ── CIS Compliance (full report view) ────────────────────────────────────────
function CompliancePage() {
  return (
    <div>
      <div className="bg-gradient-to-r from-[--green-50] to-white border border-[--gray-200] rounded-lg shadow-card border-l-4 border-l-[--green-600] p-4 mb-4">
        <div className="flex items-start gap-3">
          <span className="text-2xl mt-0.5">📋</span>
          <div>
            <h1 className="text-base font-bold text-[--gray-900] mb-0.5">CIS Compliance</h1>
            <p className="text-xs text-[--gray-500] mb-1.5">CIS Controls v8 · macOS Benchmark · 53 controls assessed</p>
            <p className="text-xs text-[--gray-600] leading-relaxed max-w-3xl">
              The Center for Internet Security (CIS) Controls v8 is the industry-standard prioritized set of actions to protect against the most prevalent cyber attacks. The macOS CIS Benchmark provides 53 specific configuration checks across 12 control families. A 34% pass rate means the fundamental attack surface is largely unconfigured. CIS Controls 1–6 (basic cyber hygiene) should be achieved before investing in advanced detection tooling.
            </p>
          </div>
        </div>
      </div>
      <div className="grid grid-cols-3 gap-3">
        {[
          ["CIS-1",  60, "Asset Inventory",           "hardware · software · sbom"],
          ["CIS-2",  45, "Software Asset Mgmt",        "apps · packages · binaries"],
          ["CIS-4",  12, "Secure Configuration",       "SIP · Gatekeeper · FileVault"],
          ["CIS-5",  25, "Account Management",         "UID-0 · admin accounts"],
          ["CIS-6",  38, "Access Control Mgmt",        "sudo · permissions"],
          ["CIS-7",  20, "Vulnerability Management",   "CVE patching · EPSS"],
          ["CIS-8",  55, "Audit Log Management",       "audit daemon · log retention"],
          ["CIS-10", 72, "Malware Defenses",           "XProtect · Gatekeeper"],
          ["CIS-12", 50, "Network Infrastructure",     "firewall · ports · DNS"],
        ].map(([id, pct, title, detail]) => (
          <CISCard key={id as string} controlId={id as string} percentage={pct as number} title={title as string} failDetails={detail as string} />
        ))}
      </div>
    </div>
  );
}

// ── Raw Data page ─────────────────────────────────────────────────────────────
function RawDataPage() {
  return (
    <div>
      <div className="bg-gradient-to-r from-[--gray-50] to-white border border-[--gray-200] rounded-lg shadow-card border-l-4 border-l-[--gray-400] p-4 mb-4">
        <div className="flex items-start gap-3">
          <span className="text-2xl mt-0.5">🗄</span>
          <div>
            <h1 className="text-base font-bold text-[--gray-900] mb-0.5">Raw Telemetry Data</h1>
            <p className="text-xs text-[--gray-500] mb-1.5">Three-tier NDJSON+gzip store · 25+ sections · hot/warm/cold tiers</p>
            <p className="text-xs text-[--gray-600] leading-relaxed max-w-3xl">
              Every 10 seconds, the agent collects 25+ telemetry sections — processes, connections, metrics, packages, users, services, security posture, and more. Raw data is stored in NDJSON+gzip flat files organized in three tiers: hot (last 24h, per-minute buckets), warm (1–90 days, per-hour buckets), cold (90d–1yr, per-day buckets). Use this view to query raw telemetry for forensic investigation or baseline analysis.
            </p>
            <div className="flex gap-2 mt-2">
              {["metrics","processes","connections","packages","users","services","security","hardware"].map(s => (
                <span key={s} className="px-2 py-0.5 bg-[--gray-100] text-[--gray-600] border border-[--gray-200] rounded text-[10px] font-mono">{s}</span>
              ))}
              <span className="text-[10px] text-[--gray-400]">+ 17 more</span>
            </div>
          </div>
        </div>
      </div>
      <div className="bg-white border border-[--gray-200] rounded-lg shadow-card p-6 text-center">
        <div className="text-4xl mb-3">📂</div>
        <div className="text-sm font-semibold text-[--gray-700] mb-1">Raw Telemetry Explorer</div>
        <div className="text-xs text-[--gray-500]">Select an agent and section to browse raw NDJSON telemetry records</div>
        <div className="flex justify-center gap-2 mt-4">
          <select className="px-3 py-2 text-xs border border-[--gray-200] rounded-md bg-white text-[--gray-700]">
            <option>mac-a1b2 · Rutik-MacBook-Pro</option>
            <option>mac-c3d4 · eng-mbp-02</option>
          </select>
          <select className="px-3 py-2 text-xs border border-[--gray-200] rounded-md bg-white text-[--gray-700]">
            <option>processes</option>
            <option>connections</option>
            <option>metrics</option>
            <option>packages</option>
          </select>
          <select className="px-3 py-2 text-xs border border-[--gray-200] rounded-md bg-white text-[--gray-700]">
            <option>Last 5 minutes</option>
            <option>Last 1 hour</option>
            <option>Last 24 hours</option>
          </select>
          <button className="px-4 py-2 bg-[--brand-orange] text-white text-xs font-semibold rounded-md hover:bg-[--brand-orange-700] transition-colors">
            Query
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Router ────────────────────────────────────────────────────────────────────
function PageRouter({ page }: { page: PageId }) {
  switch (page) {
    case "command-center":  return <CommandCenter />;
    case "threat-queue":    return <ThreatQueue />;
    case "execution":       return <ExecutionThreats />;
    case "network":         return <NetworkThreats />;
    case "vulnerabilities": return <VulnerabilitySurface />;
    case "persistence":     return <PersistenceBackdoors />;
    case "identity":        return <IdentityAccess />;
    case "security-posture":return <SecurityPosture />;
    case "compliance":      return <CompliancePage />;
    case "attack-chains":   return <AttackChains />;
    case "threat-intel":    return <ThreatIntelligence />;
    case "ai-analyst":      return <AIAnalyst />;
    case "timeline":        return <Timeline />;
    case "assets":          return <AssetRegistry />;
    case "raw-data":        return <RawDataPage />;
    default:                return <CommandCenter />;
  }
}

// ── App ───────────────────────────────────────────────────────────────────────
export default function App() {
  const [activePage, setActivePage] = useState<PageId>("command-center");

  return (
    <div className="flex h-screen bg-gradient-to-br from-[--gray-25] to-[--gray-50]">
      <Sidebar activePage={activePage} onNavigate={setActivePage} />

      <div className="flex-1 flex flex-col overflow-hidden min-w-0">
        <TopHeader />

        <div className="flex-1 overflow-y-auto p-5 bg-gradient-to-br from-[--gray-25] via-white to-[--gray-50]">
          <div className="max-w-[1200px] mx-auto">
            <PageRouter page={activePage} />
          </div>
        </div>
      </div>
    </div>
  );
}
