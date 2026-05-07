import { useState } from "react";
import { Anchor } from "lucide-react";
import { PageHeader, FilterBar, FindingsTable, SectionHeading, type Finding } from "./shared";

const MOCK: Finding[] = [
  { id: 401, title: "Unknown LaunchDaemon registered at 02:14", category: "service", severity: "critical", score: 9.1, mitre_technique: "T1543.004", mitre_tactic: "Persistence", agent_id: "mac-a1b2", first_detected_at: 1746599400, last_detected_at: 1746621600, status: "new", description: "com.update-helper.plist appeared at /Library/LaunchDaemons/ at 02:14 local time. No matching installer receipt in pkg db. Binary at /usr/local/bin/.helper (hidden dot-prefix)." },
  { id: 402, title: "Login item added for non-App-Store binary", category: "service", severity: "high", score: 8.3, mitre_technique: "T1547.001", mitre_tactic: "Persistence", agent_id: "mac-c3d4", first_detected_at: 1746605000, last_detected_at: 1746621600, status: "triaging", description: "Login item 'SyncHelper' added pointing to /Users/user/Library/.sync/agent — not code-signed, not in Gatekeeper DB" },
  { id: 403, title: "Cron job added by non-root user", category: "service", severity: "high", score: 7.8, mitre_technique: "T1053.003", mitre_tactic: "Persistence", agent_id: "mac-e5f6", first_detected_at: 1746610000, last_detected_at: 1746621600, status: "new", description: "crontab entry: '*/15 * * * * /tmp/.x >/dev/null 2>&1' added by uid=501. /tmp/.x is a 47KB ELF binary." },
  { id: 404, title: "LaunchAgent in hidden dot-directory", category: "service", severity: "high", score: 7.5, mitre_technique: "T1543.001", mitre_tactic: "Persistence", agent_id: "mac-g7h8", first_detected_at: 1746608000, last_detected_at: 1746621600, status: "investigating", description: "~/Library/.agents/com.apple.syncservice.plist — spoofing Apple naming convention. RunAtLoad=true, KeepAlive=true." },
  { id: 405, title: "Periodic maintenance script modified", category: "service", severity: "medium", score: 6.2, mitre_technique: "T1053.003", mitre_tactic: "Persistence", agent_id: "mac-a1b2", first_detected_at: 1746601000, last_detected_at: 1746621600, status: "triaging", description: "/etc/periodic/daily/900.backup modified mtime changed. New content appends curl download-and-exec." },
  { id: 406, title: "KextManager-loaded unsigned kernel extension", category: "service", severity: "medium", score: 5.9, mitre_technique: "T1547.006", mitre_tactic: "Persistence", agent_id: "mac-c3d4", first_detected_at: 1746595000, last_detected_at: 1746621600, status: "new", description: "Kext 'com.anon.driver' loaded — not Apple-signed, not from known vendor. Kexts have kernel-level access." },
];

const KNOWN_GOOD = [
  "com.apple.mdmclient.plist",
  "com.apple.AirPlayXPCHelper.plist",
  "com.apple.softwareupdated.plist",
];

export default function PersistenceBackdoors() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");

  const filtered = MOCK.filter(f =>
    (!severity || f.severity === severity) &&
    (!status   || f.status   === status)   &&
    (!search   || f.title.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div>
      <PageHeader
        icon={<Anchor className="w-6 h-6 text-[--purple-600]" />}
        title="Persistence & Backdoors"
        subtitle="LaunchDaemons · LaunchAgents · cron jobs · login items · kexts"
        backstory="Every advanced threat actor establishes persistence after initial access. APT41 abuses LaunchDaemons (T1543.004); Lazarus Group uses Login Items (T1547.001); multiple ransomware operators use cron jobs for re-infection resilience. A new LaunchDaemon outside a known software installer context is a near-definitive indicator of compromise — macOS installers always leave a pkg receipt. No receipt + hidden binary path = backdoor. The time-of-creation signal matters too: 02:14 local time, no interactive session = automated install."
        accentClass="border-l-[--purple-600]"
        bgClass="from-[--purple-50]"
        tactics={["TA0003 · Persistence", "TA0005 · Defense Evasion"]}
        techniqueIds={[
          { id: "T1543.004", label: "LaunchDaemon" },
          { id: "T1547.001", label: "Login Item" },
          { id: "T1053.003", label: "Cron Job" },
          { id: "T1547.006", label: "Kernel Module" },
        ]}
        kpis={[
          { label: "New LaunchDaemons", value: 1, color: "red"    },
          { label: "Unsigned Login Items", value: 1, color: "red"   },
          { label: "Cron Additions",    value: 2, color: "amber"  },
          { label: "Total Persistence", value: MOCK.length, color: "amber" },
        ]}
      />

      <FilterBar search={search} onSearch={setSearch} severity={severity} onSeverity={setSeverity} status={status} onStatus={setStatus} />
      <FindingsTable findings={filtered} />

      <div className="mt-4">
        <SectionHeading title="Known-good LaunchDaemons (baseline)" color="green" />
        <div className="bg-white border border-[--gray-200] rounded-lg shadow-card p-3">
          <div className="flex flex-wrap gap-2">
            {KNOWN_GOOD.map(p => (
              <span key={p} className="px-2 py-1 bg-[--green-50] text-[--green-700] border border-[--green-600]/20 rounded text-[10px] font-mono">{p}</span>
            ))}
            <span className="px-2 py-1 text-[--gray-400] text-[10px]">+ 47 more Apple system daemons</span>
          </div>
          <p className="text-[10px] text-[--gray-500] mt-2">These are suppressed from findings — any LaunchDaemon NOT in this allowlist is flagged for review.</p>
        </div>
      </div>
    </div>
  );
}
