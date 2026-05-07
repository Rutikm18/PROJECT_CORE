import { Crosshair } from "lucide-react";
import { PageHeader, SectionHeading, KevBadge } from "./shared";

interface Feed {
  name: string;
  type: string;
  iocs: number;
  matches: number;
  updated: string;
  status: "live" | "ok" | "warn";
  description: string;
}

const FEEDS: Feed[] = [
  { name: "CISA KEV",          type: "Vulnerability", iocs: 1123,  matches: 2,  updated: "1h ago",  status: "live", description: "CISA Known Exploited Vulnerabilities catalog — CVEs actively exploited against US federal agencies. A KEV match = patch immediately." },
  { name: "Feodo Tracker",     type: "C2 IPs",        iocs: 5840,  matches: 1,  updated: "1h ago",  status: "live", description: "Abuse.ch Feodo Tracker — Emotet, IcedID, Dridex, QakBot, and TrickBot C2 infrastructure. Match = known botnet C2." },
  { name: "ThreatFox",         type: "IOCs (multi)",  iocs: 98432, matches: 2,  updated: "30m ago", status: "live", description: "Abuse.ch multi-type IOC database — IPs, URLs, domains, file hashes for 200+ malware families. High-confidence threat actor attribution." },
  { name: "Emerging Threats",  type: "IDS Rules",     iocs: 41230, matches: 3,  updated: "1h ago",  status: "ok",   description: "ProofPoint Emerging Threats Open ruleset — community-maintained IDS signatures for C2, malware delivery, and exploitation." },
  { name: "NVD / EPSS",        type: "Vulnerability", iocs: 236847,matches: 8,  updated: "live",    status: "live", description: "NIST National Vulnerability Database with FIRST.org EPSS scores. Provides CVSS vectors and 30-day exploitation probability for all CVEs." },
  { name: "ransomware.live",   type: "Ransomware",    iocs: 4213,  matches: 0,  updated: "2h ago",  status: "ok",   description: "Real-time ransomware group activity tracker — victim posts, infrastructure, and IoCs from 90+ active groups." },
  { name: "Spamhaus DROP",     type: "IP Blocklist",  iocs: 1847,  matches: 0,  updated: "1h ago",  status: "ok",   description: "Spamhaus Don't Route Or Peer lists — IP ranges owned by professional spam/cybercrime operations. No legitimate traffic uses these ranges." },
  { name: "URLhaus",           type: "Malware URLs",  iocs: 234567,matches: 0,  updated: "30m ago", status: "live", description: "Abuse.ch URLhaus — active malware distribution URLs, payload hosting, and drive-by download infrastructure." },
  { name: "AbuseIPDB",         type: "IP Reputation", iocs: 0,     matches: 0,  updated: "live",    status: "warn", description: "Community IP reputation database with confidence scores. API key required for full resolution." },
  { name: "OTX",               type: "Threat Intel",  iocs: 0,     matches: 0,  updated: "—",       status: "warn", description: "AlienVault Open Threat Exchange — threat actor campaigns, IoC pulses, and attack pattern sharing. API key not configured." },
];

const IOC_MATCHES = [
  { ioc: "185.220.101.47", type: "IP", feed: "Feodo Tracker",  threat: "Emotet C2", confidence: "HIGH",   last_seen: "6h ago",  agent: "mac-c3d4" },
  { ioc: "193.42.33.88",   type: "IP", feed: "ThreatFox",      threat: "Cobalt Strike C2", confidence: "HIGH", last_seen: "4h ago", agent: "mac-e5f6" },
  { ioc: "CVE-2024-44308", type: "CVE",feed: "CISA KEV",       threat: "Active Exploitation", confidence: "CONFIRMED", last_seen: "1h ago", agent: "mac-a1b2" },
  { ioc: "CVE-2023-32373", type: "CVE",feed: "CISA KEV",       threat: "Active Exploitation", confidence: "CONFIRMED", last_seen: "1h ago", agent: "mac-c3d4" },
  { ioc: "TCP:4444",       type: "Port",feed: "Emerging Threats","threat": "DarkComet C2", confidence: "MEDIUM", last_seen: "2h ago", agent: "mac-e5f6" },
];

export default function ThreatIntelligence() {
  const totalMatches = FEEDS.reduce((a, f) => a + f.matches, 0);
  const liveFeeds = FEEDS.filter(f => f.status === "live").length;
  const kevMatches = FEEDS.find(f => f.name === "CISA KEV")?.matches ?? 0;

  return (
    <div>
      <PageHeader
        icon={<Crosshair className="w-6 h-6 text-[--blue-600]" />}
        title="Threat Intelligence"
        subtitle="10+ live feeds · IOC correlation · CISA KEV · threat actor context"
        backstory="Context transforms findings into intelligence. An outbound connection to an unknown IP is suspicious; a connection to infrastructure used by Emotet in the last 6 hours is an incident requiring immediate containment. CISA KEV tracks vulnerabilities actively exploited against US federal agencies — a KEV match means real attackers are weaponizing this CVE right now, not theoretically. All feeds refresh hourly and are cached locally so detection never blocks on network I/O."
        accentClass="border-l-[--blue-600]"
        bgClass="from-[--blue-50]"
        tactics={["Threat Intelligence", "IOC Enrichment", "Feed Management"]}
        kpis={[
          { label: "Active Feeds",    value: liveFeeds,    color: "green" },
          { label: "Total IOC Matches",value: totalMatches, color: "red"   },
          { label: "KEV Matches",     value: kevMatches,   color: "red"   },
          { label: "Total IOCs",      value: "590K+",      color: "blue"  },
        ]}
      />

      <div className="grid grid-cols-[1fr_340px] gap-4">
        {/* Feed status */}
        <div>
          <SectionHeading title="Feed Status" count={FEEDS.length} color="blue" />
          <div className="bg-white border border-[--gray-200] rounded-lg shadow-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-gradient-to-r from-[--gray-25] to-white border-b border-[--gray-200]">
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Feed</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Type</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">IOCs</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Matches</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Updated</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Status</th>
                </tr>
              </thead>
              <tbody>
                {FEEDS.map(f => (
                  <tr key={f.name} className="border-b border-[--gray-100] hover:bg-[--gray-25] group">
                    <td className="px-3 py-2.5">
                      <div className="font-medium text-[--gray-800]">{f.name}</div>
                      <div className="text-[10px] text-[--gray-400] max-w-xs leading-relaxed opacity-0 group-hover:opacity-100 transition-opacity">{f.description}</div>
                    </td>
                    <td className="px-3 py-2.5 text-[--gray-500]">{f.type}</td>
                    <td className="px-3 py-2.5 font-medium text-[--gray-700]">
                      {f.iocs > 0 ? f.iocs.toLocaleString() : <span className="text-[--gray-300]">—</span>}
                    </td>
                    <td className="px-3 py-2.5">
                      {f.matches > 0
                        ? <span className="font-bold text-[--red-600]">{f.matches}</span>
                        : <span className="text-[--gray-300]">0</span>}
                    </td>
                    <td className="px-3 py-2.5 text-[--gray-500]">{f.updated}</td>
                    <td className="px-3 py-2.5">
                      {f.status === "live" && <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-[--green-500] animate-pulse" />Live</span>}
                      {f.status === "ok"   && <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-[--blue-500]" />OK</span>}
                      {f.status === "warn" && <span className="flex items-center gap-1 text-[--amber-600]"><span className="w-1.5 h-1.5 rounded-full bg-[--amber-500]" />No API key</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* IOC matches */}
        <div>
          <SectionHeading title="Active IOC Matches" count={IOC_MATCHES.length} color="red" />
          <div className="space-y-2">
            {IOC_MATCHES.map((m, i) => (
              <div key={i} className="bg-white border border-[--gray-200] rounded-lg p-3 shadow-card border-l-4 border-l-[--red-500]">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="font-mono font-semibold text-xs text-[--gray-900]">{m.ioc}</div>
                    <div className="text-[10px] text-[--gray-500] mt-0.5">{m.type} · {m.feed}</div>
                  </div>
                  {m.type === "CVE" && <KevBadge />}
                  {m.type !== "CVE" && (
                    <span className={`px-1.5 py-0.5 text-[10px] font-bold rounded border ${m.confidence === "CONFIRMED" ? "bg-[--red-100] text-[--red-700] border-[--red-600]/30" : m.confidence === "HIGH" ? "bg-[--amber-100] text-[--amber-700] border-[--amber-600]/30" : "bg-[--blue-100] text-[--blue-700] border-[--blue-600]/30"}`}>
                      {m.confidence}
                    </span>
                  )}
                </div>
                <div className="text-[10px] font-medium text-[--red-700] mt-1">{m.threat}</div>
                <div className="flex items-center justify-between mt-1 text-[10px] text-[--gray-400]">
                  <span>{m.agent}</span>
                  <span>{m.last_seen}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
