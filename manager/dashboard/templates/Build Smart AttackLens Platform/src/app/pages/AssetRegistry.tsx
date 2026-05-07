import { Monitor } from "lucide-react";
import { PageHeader, SectionHeading } from "./shared";

interface Agent {
  id: string;
  hostname: string;
  os: string;
  ip: string;
  enrolled: string;
  last_seen: string;
  status: "healthy" | "stale" | "offline";
  findings: { critical: number; high: number; medium: number };
  tier: "critical" | "important" | "standard";
  model?: string;
}

const AGENTS: Agent[] = [
  { id: "mac-a1b2", hostname: "Rutik-MacBook-Pro",    os: "macOS 14.4.1 (Sonoma)", ip: "192.168.1.42", enrolled: "7 days ago", last_seen: "10s ago",  status: "healthy", findings: { critical: 4, high: 3, medium: 2 }, tier: "critical",  model: "MacBook Pro M3 Max" },
  { id: "mac-c3d4", hostname: "eng-mbp-02",            os: "macOS 14.4.0 (Sonoma)", ip: "192.168.1.55", enrolled: "14 days ago",last_seen: "25s ago",  status: "healthy", findings: { critical: 2, high: 4, medium: 3 }, tier: "important", model: "MacBook Pro M2" },
  { id: "mac-e5f6", hostname: "design-studio-air",     os: "macOS 13.6.4 (Ventura)",ip: "192.168.1.67", enrolled: "3 days ago", last_seen: "1m ago",   status: "healthy", findings: { critical: 1, high: 3, medium: 5 }, tier: "important", model: "MacBook Air M2" },
  { id: "mac-g7h8", hostname: "devops-macpro-01",      os: "macOS 14.3.1 (Sonoma)", ip: "192.168.1.78", enrolled: "21 days ago",last_seen: "2m ago",   status: "stale",   findings: { critical: 0, high: 2, medium: 4 }, tier: "standard",  model: "Mac Pro M2 Ultra" },
  { id: "mac-i9j0", hostname: "ceo-macbook",           os: "macOS 14.4.1 (Sonoma)", ip: "10.0.0.5",     enrolled: "1 day ago",  last_seen: "18m ago",  status: "stale",   findings: { critical: 0, high: 1, medium: 2 }, tier: "critical",  model: "MacBook Pro M3" },
];

const TIER_COLORS: Record<string, string> = {
  critical:  "bg-[--red-50] text-[--red-700] border-[--red-600]/20",
  important: "bg-[--amber-50] text-[--amber-700] border-[--amber-500]/20",
  standard:  "bg-[--gray-100] text-[--gray-600] border-[--gray-300]",
};

const STATUS_DOT: Record<string, string> = {
  healthy: "bg-[--green-500] animate-pulse",
  stale:   "bg-[--amber-500]",
  offline: "bg-[--gray-300]",
};

export default function AssetRegistry() {
  const totalFindings = AGENTS.reduce((a, ag) => a + ag.findings.critical + ag.findings.high + ag.findings.medium, 0);
  const healthy = AGENTS.filter(a => a.status === "healthy").length;

  return (
    <div>
      <PageHeader
        icon={<Monitor className="w-6 h-6 text-[--gray-600]" />}
        title="Asset Registry"
        subtitle="Enrolled agents · hardware inventory · asset tier scoring · health status"
        backstory="CIS Control 1 states: 'You cannot protect what you don't know about.' The asset registry is the foundation of all risk scoring — every finding is weighted against the enrolled asset's tier (critical/important/standard). The CFO's laptop with an unpatched CVE scores higher than the build server with the same CVE, because the business impact of compromise differs. An agent that hasn't reported in over 5 minutes warrants investigation — it may have crashed, been tampered with, or lost connectivity."
        accentClass="border-l-[--gray-500]"
        bgClass="from-[--gray-50]"
        tactics={["CIS Control 1", "Asset Management"]}
        kpis={[
          { label: "Total Agents",  value: AGENTS.length, color: "blue"  },
          { label: "Healthy",       value: healthy,       color: "green" },
          { label: "Stale / Offline", value: AGENTS.length - healthy, color: "amber" },
          { label: "Total Findings",value: totalFindings,  color: "amber" },
        ]}
      />

      <SectionHeading title="Enrolled Agents" count={AGENTS.length} color="gray" />

      <div className="bg-white border border-[--gray-200] rounded-lg shadow-card overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-gradient-to-r from-[--gray-25] to-white border-b border-[--gray-200]">
              <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Agent</th>
              <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">OS</th>
              <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">IP</th>
              <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Tier</th>
              <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Findings</th>
              <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Last Seen</th>
              <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Status</th>
            </tr>
          </thead>
          <tbody>
            {AGENTS.map(a => (
              <tr key={a.id} className="border-b border-[--gray-100] hover:bg-[--gray-25] cursor-pointer transition-colors">
                <td className="px-3 py-2.5">
                  <div className="font-medium text-[--gray-800]">{a.hostname}</div>
                  <div className="text-[10px] text-[--gray-400] font-mono">{a.id} · {a.model}</div>
                </td>
                <td className="px-3 py-2.5 text-[--gray-600]">{a.os}</td>
                <td className="px-3 py-2.5 font-mono text-[--gray-600] text-[10px]">{a.ip}</td>
                <td className="px-3 py-2.5">
                  <span className={`px-2 py-0.5 text-[10px] font-semibold rounded border capitalize ${TIER_COLORS[a.tier]}`}>{a.tier}</span>
                </td>
                <td className="px-3 py-2.5">
                  <div className="flex items-center gap-1.5">
                    {a.findings.critical > 0 && (
                      <span className="px-1.5 py-0.5 bg-[--red-100] text-[--red-700] rounded text-[10px] font-bold">{a.findings.critical}C</span>
                    )}
                    {a.findings.high > 0 && (
                      <span className="px-1.5 py-0.5 bg-[--amber-100] text-[--amber-700] rounded text-[10px] font-bold">{a.findings.high}H</span>
                    )}
                    {a.findings.medium > 0 && (
                      <span className="px-1.5 py-0.5 bg-[--blue-100] text-[--blue-700] rounded text-[10px] font-semibold">{a.findings.medium}M</span>
                    )}
                  </div>
                </td>
                <td className="px-3 py-2.5 text-[--gray-500]">{a.last_seen}</td>
                <td className="px-3 py-2.5">
                  <div className="flex items-center gap-1.5">
                    <div className={`w-1.5 h-1.5 rounded-full ${STATUS_DOT[a.status]}`} />
                    <span className={`text-[10px] font-medium capitalize ${a.status === "healthy" ? "text-[--green-700]" : a.status === "stale" ? "text-[--amber-700]" : "text-[--gray-500]"}`}>
                      {a.status}
                    </span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Enrollment stats */}
      <div className="mt-4 grid grid-cols-3 gap-3">
        {(["critical", "important", "standard"] as const).map(tier => {
          const agents = AGENTS.filter(a => a.tier === tier);
          const findings = agents.reduce((a, ag) => a + ag.findings.critical * 3 + ag.findings.high * 2 + ag.findings.medium, 0);
          return (
            <div key={tier} className={`bg-white border rounded-lg p-3 shadow-card border-l-4 ${tier === "critical" ? "border-l-[--red-500]" : tier === "important" ? "border-l-[--amber-500]" : "border-l-[--gray-300]"}`}>
              <div className="text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide mb-1">{tier} tier</div>
              <div className="text-2xl font-bold text-[--gray-900]">{agents.length}</div>
              <div className="text-[10px] text-[--gray-500]">agents · {findings} weighted findings</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
