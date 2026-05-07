import { useState } from "react";
import { Globe } from "lucide-react";
import { PageHeader, FilterBar, FindingsTable, SectionHeading, SevBadge, MitreBadge, type Finding } from "./shared";

const MOCK: Finding[] = [
  { id: 201, title: "C2 beaconing — entropy 0.8, 30s interval", category: "connection", severity: "critical", score: 9.2, mitre_technique: "T1071.001", mitre_tactic: "C2", agent_id: "mac-a1b2", first_detected_at: 1746600000, last_detected_at: 1746621600, status: "new", description: "18 outbound HTTPS connections to 3 IPs; Shannon entropy 0.8 (threshold 1.2); 30s±2s jitter — automated beaconing signature" },
  { id: 202, title: "Known Feodo C2 tracker IP contact", category: "connection", severity: "critical", score: 9.0, mitre_technique: "T1071.001", mitre_tactic: "C2", agent_id: "mac-c3d4", first_detected_at: 1746612000, last_detected_at: 1746621600, status: "new", description: "185.220.101.47 matched Feodo Tracker — known Emotet/IcedID C2 infrastructure. Active as of 6h ago.", kev: true },
  { id: 203, title: "Outbound connection to ThreatFox IOC", category: "connection", severity: "high", score: 8.5, mitre_technique: "T1071", mitre_tactic: "C2", agent_id: "mac-e5f6", first_detected_at: 1746609000, last_detected_at: 1746621600, status: "triaging", description: "193.42.33.88:4444 matched ThreatFox database — tagged Cobalt Strike C2, confidence HIGH" },
  { id: 204, title: "Large data transfer to unknown external IP", category: "connection", severity: "high", score: 8.1, mitre_technique: "T1048", mitre_tactic: "Exfiltration", agent_id: "mac-a1b2", first_detected_at: 1746615000, last_detected_at: 1746621600, status: "investigating", description: "847MB sent to 45.77.x.x over 22 minutes via port 443 — volume 9.3× above this agent's 30-day baseline" },
  { id: 205, title: "Port scan pattern — high entropy 5.2, 40 dests", category: "connection", severity: "medium", score: 6.9, mitre_technique: "T1046", mitre_tactic: "Discovery", agent_id: "mac-g7h8", first_detected_at: 1746614400, last_detected_at: 1746621600, status: "new", description: "40 unique destination IPs in 5 minutes, entropy 5.2 — internal subnet scan (192.168.1.0/24) from non-service process" },
  { id: 206, title: "DNS over HTTPS to non-corporate resolver", category: "connection", severity: "medium", score: 6.2, mitre_technique: "T1071.004", mitre_tactic: "C2", agent_id: "mac-c3d4", first_detected_at: 1746605000, last_detected_at: 1746621600, status: "new", description: "DoH queries to 1.1.1.1 and 9.9.9.9 bypassing corporate DNS — common C2 DNS tunneling evasion technique" },
  { id: 207, title: "ET Rules match — Emerging Threats signature", category: "connection", severity: "medium", score: 5.9, mitre_technique: "T1071", mitre_tactic: "C2", agent_id: "mac-e5f6", first_detected_at: 1746610000, last_detected_at: 1746621600, status: "triaging", description: "Emerging Threats Open ruleset match: ET MALWARE Possible DarkComet C2 Activity (TCP)" },
];

const BEACON_CANDIDATES = [
  { ip: "185.220.101.47", port: 443, count: 18, entropy: 0.8, interval: "30s ±2s", feed: "Feodo Tracker", verdict: "C2 confirmed" },
  { ip: "193.42.33.88",   port: 4444, count: 12, entropy: 1.1, interval: "45s ±5s", feed: "ThreatFox",     verdict: "C2 confirmed" },
  { ip: "45.77.182.13",   port: 443, count: 9,  entropy: 2.1, interval: "irregular", feed: "—",           verdict: "Investigating" },
];

export default function NetworkThreats() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [tab, setTab] = useState<"findings" | "beaconing">("findings");

  const filtered = MOCK.filter(f =>
    (!severity || f.severity === severity) &&
    (!status   || f.status   === status)   &&
    (!search   || f.title.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div>
      <PageHeader
        icon={<Globe className="w-6 h-6 text-[--blue-600]" />}
        title="Network Threats"
        subtitle="C2 beaconing · exfiltration · threat feed IOC matches · scanning"
        backstory="Average attacker dwell time before detection is 10 days (Mandiant M-Trends 2024). During that window, C2 beaconing is the primary evidence trail. Shannon entropy analysis catches beaconing even when the destination is unknown — a fixed set of IPs contacted at regular intervals has entropy < 1.2 regardless of what threat feeds say. A confirmed Feodo or ThreatFox IOC match escalates response from 'investigate' to 'contain immediately' — these are known active threat actor infrastructure."
        accentClass="border-l-[--blue-600]"
        bgClass="from-[--blue-50]"
        tactics={["TA0011 · C2", "TA0010 · Exfiltration", "TA0007 · Discovery"]}
        techniqueIds={[
          { id: "T1071.001", label: "Web Protocols C2" },
          { id: "T1048",     label: "Exfil over C2" },
          { id: "T1046",     label: "Network Service Scan" },
        ]}
        kpis={[
          { label: "C2 Connections",  value: 3, color: "red"   },
          { label: "Feed IOC Matches",value: 2, color: "red"   },
          { label: "Beaconing IPs",   value: 2, color: "amber" },
          { label: "Data Volume (MB)",value: 847, color: "amber" },
        ]}
      />

      <div className="flex gap-1 mb-3">
        {(["findings", "beaconing"] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors ${tab === t ? "bg-[--blue-600] text-white" : "bg-white border border-[--gray-200] text-[--gray-600] hover:bg-[--gray-50]"}`}>
            {t === "beaconing" ? "Beaconing Analysis" : "Findings"}
          </button>
        ))}
      </div>

      {tab === "findings" && (
        <>
          <FilterBar search={search} onSearch={setSearch} severity={severity} onSeverity={setSeverity} status={status} onStatus={setStatus} />
          <FindingsTable findings={filtered} />
        </>
      )}

      {tab === "beaconing" && (
        <div className="space-y-3">
          <SectionHeading title="Beaconing Candidates — Shannon Entropy Analysis" count={BEACON_CANDIDATES.length} color="blue" />
          <div className="text-xs text-[--gray-500] mb-2 bg-[--blue-50] border border-[--blue-600]/20 rounded-lg px-3 py-2">
            <strong className="text-[--blue-700]">How entropy detection works:</strong> Shannon entropy H = −Σ p(ip) log₂ p(ip) over outbound destination IPs.
            Entropy &lt; 1.2 = same few IPs repeatedly = beaconing. Entropy &gt; 4.5 = many unique IPs = scanning. Legitimate browsing: entropy 3.5–4.5.
          </div>
          <div className="bg-white border border-[--gray-200] rounded-lg shadow-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-gradient-to-r from-[--gray-25] to-white border-b border-[--gray-200]">
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">IP</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Port</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Connections</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Entropy</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Interval</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Feed Match</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Verdict</th>
                </tr>
              </thead>
              <tbody>
                {BEACON_CANDIDATES.map((b, i) => (
                  <tr key={i} className="border-b border-[--gray-100] hover:bg-[--gray-25]">
                    <td className="px-3 py-2.5 font-mono text-[--gray-800]">{b.ip}</td>
                    <td className="px-3 py-2.5 font-mono text-[--gray-600]">{b.port}</td>
                    <td className="px-3 py-2.5 font-medium text-[--gray-700]">{b.count}</td>
                    <td className="px-3 py-2.5">
                      <span className={`font-bold ${b.entropy < 1.2 ? "text-[--red-600]" : "text-[--amber-600]"}`}>{b.entropy}</span>
                      <span className="text-[--gray-400] ml-1">{b.entropy < 1.2 ? "← LOW" : ""}</span>
                    </td>
                    <td className="px-3 py-2.5 text-[--gray-600]">{b.interval}</td>
                    <td className="px-3 py-2.5">
                      {b.feed !== "—" ? (
                        <span className="px-1.5 py-0.5 bg-[--red-50] text-[--red-700] border border-[--red-600]/20 rounded text-[10px] font-semibold">{b.feed}</span>
                      ) : (
                        <span className="text-[--gray-400]">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      <SevBadge sev={b.verdict === "C2 confirmed" ? "critical" : "medium"} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
