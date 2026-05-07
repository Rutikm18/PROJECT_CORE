import { useState } from "react";
import { Bot, Sparkles, ChevronDown, ChevronUp } from "lucide-react";
import { PageHeader, SectionHeading, SevBadge } from "./shared";

interface AIFinding {
  id: number;
  title: string;
  severity: "critical" | "high" | "medium";
  score: number;
  ai_summary: string;
  remediation: string[];
  mitre: string;
  enriched: boolean;
  agent_id: string;
}

const AI_FINDINGS: AIFinding[] = [
  {
    id: 1,
    title: "Cobalt Strike beacon — csrss-helper",
    severity: "critical",
    score: 9.7,
    mitre: "T1071.001",
    agent_id: "mac-a1b2",
    enriched: true,
    ai_summary: "This finding has high confidence characteristics of an active Cobalt Strike deployment. The process entropy signature (7.8), 96-byte heartbeat payload, and 30-second beacon interval are consistent with default Cobalt Strike Malleable C2 profiles. The process name 'csrss-helper' mimics a legitimate Windows system process (csrss.exe) — a well-documented APT naming convention for macOS implants. Immediate isolation is recommended. Priority: P0.",
    remediation: [
      "1. Immediately isolate the endpoint: `sudo pfctl -e && sudo pfctl -f /etc/pf.conf` to block all outbound traffic",
      "2. Kill the malicious process: `sudo kill -9 $(pgrep csrss-helper)`",
      "3. Identify persistence: `launchctl list | grep -v apple` and review /Library/LaunchDaemons/",
      "4. Capture memory for forensics before remediation: `sudo osxpmem -o /tmp/memory.aff4`",
      "5. Re-image the endpoint. Do not trust any process running on this machine.",
      "6. Rotate all credentials that were accessible from this endpoint (keychain, SSH keys, browser-stored passwords)",
    ],
  },
  {
    id: 2,
    title: "CVE-2024-44308 — curl 7.86.0 (KEV)",
    severity: "critical",
    score: 9.1,
    mitre: "T1190",
    agent_id: "mac-a1b2",
    enriched: true,
    ai_summary: "CVE-2024-44308 is a heap overflow in curl's URL parser that allows remote code execution via a maliciously crafted URL. CISA added it to KEV on 2024-01-15, indicating active exploitation in the wild. EPSS 94% means this CVE has a 94% probability of being exploited against an exposed system in the next 30 days. Given that curl is pre-installed on macOS and used by hundreds of applications via libcurl, the blast radius of non-patching is extremely high. Patch immediately.",
    remediation: [
      "1. Update curl via Homebrew: `brew upgrade curl`",
      "2. Verify: `curl --version` should show 8.6.0 or higher",
      "3. Verify linked libcurl: `otool -L /usr/bin/curl` — check all binaries linking to libcurl 7.86",
      "4. If Homebrew curl isn't system-default, set PATH: `echo 'export PATH=\"/opt/homebrew/opt/curl/bin:$PATH\"' >> ~/.zshrc`",
      "5. Restart any services that load libcurl dynamically",
    ],
  },
  {
    id: 3,
    title: "SIP disabled via recoveryOS",
    severity: "critical",
    score: 8.9,
    mitre: "T1553.001",
    agent_id: "mac-e5f6",
    enriched: true,
    ai_summary: "System Integrity Protection (SIP) is a macOS security feature that prevents even root-level processes from modifying protected system directories, kernel extensions, and security-relevant files. Its disablement is one of the most significant security events on macOS — it requires physical access or prior root compromise to disable, and its absence allows any root process to modify /System, install unsigned kernel extensions, and disable security tools. This should be treated as evidence of prior compromise unless there is a documented, authorized change record.",
    remediation: [
      "1. Re-enable SIP: Boot to recoveryOS (hold Cmd+R on Intel, hold Power on Apple Silicon)",
      "2. In Recovery: Utilities → Terminal → `csrutil enable`",
      "3. Reboot",
      "4. Verify: `csrutil status` should show 'System Integrity Protection status: enabled'",
      "5. Investigate HOW SIP was disabled — requires either physical access to recovery mode or an exploit. Check for kernel-level implants.",
      "6. Review all LaunchDaemons and kernel extensions installed while SIP was disabled — they may be malicious",
    ],
  },
];

export default function AIAnalyst() {
  const [expanded, setExpanded] = useState<number | null>(1);
  const [generating, setGenerating] = useState<number | null>(null);

  const simulateGenerate = (id: number) => {
    setGenerating(id);
    setTimeout(() => { setGenerating(null); setExpanded(id); }, 1500);
  };

  return (
    <div>
      <PageHeader
        icon={<Bot className="w-6 h-6 text-[--purple-600]" />}
        title="AI Analyst"
        subtitle="Claude-powered finding analysis · CISO prioritization · step-by-step remediation"
        backstory="Security expertise at machine speed. Claude analyzes each finding against the MITRE ATT&CK framework, available threat intelligence, EPSS/KEV context, and asset importance to generate CISO-grade prioritization and macOS-specific, copy-pasteable remediation commands. The average analyst takes 45 minutes to research a finding and write a remediation plan. AI reduces this to under 10 seconds. Findings are automatically enriched in the background — the AI analysis here is already cached and ready."
        accentClass="border-l-[--purple-600]"
        bgClass="from-[--purple-50]"
        tactics={["AI-Assisted SOC", "Automated Enrichment"]}
        kpis={[
          { label: "AI Enriched",   value: AI_FINDINGS.filter(f => f.enriched).length, color: "green" },
          { label: "Pending",       value: 4,                                           color: "amber" },
          { label: "Avg Analysis",  value: "8s",                                        color: "blue"  },
          { label: "Model",         value: "Claude",                                    color: "gray"  },
        ]}
      />

      <SectionHeading title="AI-Enriched Findings" count={AI_FINDINGS.length} color="blue" />
      <p className="text-xs text-[--gray-500] mb-3">Each analysis includes threat context, MITRE mapping, risk factors, and step-by-step macOS remediation commands.</p>

      <div className="space-y-3">
        {AI_FINDINGS.map(f => (
          <div key={f.id} className="bg-white border border-[--gray-200] rounded-lg shadow-card overflow-hidden">
            <div
              className="flex items-start justify-between p-4 cursor-pointer hover:bg-[--gray-25] transition-colors"
              onClick={() => setExpanded(expanded === f.id ? null : f.id)}
            >
              <div className="flex items-start gap-3">
                <SevBadge sev={f.severity} />
                <div>
                  <div className="font-semibold text-[--gray-900] text-sm">{f.title}</div>
                  <div className="flex items-center gap-2 mt-0.5 text-[10px] text-[--gray-500]">
                    <span className="font-mono">{f.agent_id}</span>
                    <span className="px-1.5 py-0.5 bg-[--indigo-50] text-[--indigo-600] border border-[--indigo-600]/20 rounded font-mono">{f.mitre}</span>
                    {f.enriched && (
                      <span className="flex items-center gap-1 text-[--purple-600]">
                        <Sparkles className="w-3 h-3" /> AI enriched
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                {!f.enriched && (
                  <button
                    onClick={e => { e.stopPropagation(); simulateGenerate(f.id); }}
                    disabled={generating === f.id}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-[--purple-600] text-white text-xs font-semibold rounded-md hover:bg-[--purple-600]/90 disabled:opacity-60 transition-colors"
                  >
                    {generating === f.id ? (
                      <span className="flex items-center gap-1"><span className="animate-spin">⋯</span> Analyzing…</span>
                    ) : (
                      <><Sparkles className="w-3 h-3" /> Generate</>
                    )}
                  </button>
                )}
                <span className="text-lg font-bold text-[--red-600]">{f.score}</span>
                {expanded === f.id ? <ChevronUp className="w-4 h-4 text-[--gray-400]" /> : <ChevronDown className="w-4 h-4 text-[--gray-400]" />}
              </div>
            </div>

            {expanded === f.id && f.enriched && (
              <div className="border-t border-[--gray-100] p-4 space-y-4 bg-gradient-to-br from-[--purple-50]/30 to-white">
                <div>
                  <div className="flex items-center gap-1.5 text-[10px] font-semibold text-[--purple-600] uppercase tracking-wide mb-2">
                    <Sparkles className="w-3 h-3" /> AI Security Analysis
                  </div>
                  <p className="text-xs text-[--gray-700] leading-relaxed">{f.ai_summary}</p>
                </div>
                <div>
                  <div className="text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide mb-2">Step-by-step Remediation (macOS)</div>
                  <div className="space-y-1.5">
                    {f.remediation.map((step, i) => (
                      <div key={i} className="flex gap-2 text-xs">
                        <code className="bg-[--gray-900] text-[--green-500] px-2 py-1.5 rounded text-[10px] font-mono flex-1 leading-relaxed whitespace-pre-wrap">
                          {step}
                        </code>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
