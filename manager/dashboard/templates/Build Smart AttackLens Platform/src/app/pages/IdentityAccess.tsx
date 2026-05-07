import { useState } from "react";
import { Users } from "lucide-react";
import { PageHeader, FilterBar, FindingsTable, SectionHeading, type Finding } from "./shared";

const MOCK: Finding[] = [
  { id: 501, title: "UID=0 account 'svc_backup' created without sudo flow", category: "user", severity: "critical", score: 9.3, mitre_technique: "T1136.001", mitre_tactic: "Persistence", agent_id: "mac-c3d4", first_detected_at: 1746610200, last_detected_at: 1746621600, status: "new", description: "New account svc_backup with uid=0 created directly in /etc/passwd — bypasses normal macOS admin account creation. No Installer package associated." },
  { id: 502, title: "Unexpected admin group membership change", category: "user", severity: "high", score: 8.4, mitre_technique: "T1548.003", mitre_tactic: "Privilege Escalation", agent_id: "mac-a1b2", first_detected_at: 1746608000, last_detected_at: 1746621600, status: "triaging", description: "Account 'jdoe' added to admin group at 01:42 UTC — outside business hours, no IT change ticket correlates." },
  { id: 503, title: "sudo NOPASSWD entry in /etc/sudoers", category: "user", severity: "high", score: 8.1, mitre_technique: "T1548.003", mitre_tactic: "Privilege Escalation", agent_id: "mac-e5f6", first_detected_at: 1746605000, last_detected_at: 1746621600, status: "new", description: "sudoers entry: 'user ALL=(ALL) NOPASSWD: ALL' — passwordless root escalation for uid=501. Not a standard configuration." },
  { id: 504, title: "Account login outside baseline hours (03:21 UTC)", category: "user", severity: "medium", score: 6.7, mitre_technique: "T1078", mitre_tactic: "Initial Access", agent_id: "mac-g7h8", first_detected_at: 1746620000, last_detected_at: 1746621600, status: "new", description: "User 'admin' interactive login at 03:21 UTC (local 20:21). This user's baseline shows 09:00–18:00 Mon–Fri. Credential theft or timezone anomaly." },
  { id: 505, title: "Failed sudo attempts from unknown user", category: "user", severity: "medium", score: 6.2, mitre_technique: "T1110", mitre_tactic: "Credential Access", agent_id: "mac-c3d4", first_detected_at: 1746615000, last_detected_at: 1746621600, status: "triaging", description: "47 failed sudo auth attempts from user 'guest' in 3 minutes. Password spray or bruteforce pattern." },
  { id: 506, title: "Service account used for interactive login", category: "user", severity: "low", score: 4.8, mitre_technique: "T1078.003", mitre_tactic: "Defense Evasion", agent_id: "mac-a1b2", first_detected_at: 1746590000, last_detected_at: 1746621600, status: "investigating", description: "Account '_postgres' (uid=70, service account) used for interactive shell login — service accounts should never have shell access." },
];

const ACCOUNTS = [
  { name: "root",      uid: 0,   groups: "wheel",       shell: "/bin/sh",   last_login: "never",     status: "ok" },
  { name: "svc_backup",uid: 0,   groups: "wheel,admin", shell: "/bin/bash", last_login: "3h ago",    status: "critical" },
  { name: "admin",     uid: 501, groups: "admin",       shell: "/bin/zsh",  last_login: "03:21 UTC", status: "warning" },
  { name: "jdoe",      uid: 502, groups: "admin,staff",shell: "/bin/zsh",   last_login: "9h ago",    status: "warning" },
  { name: "guest",     uid: 201, groups: "guest",       shell: "/bin/bash", last_login: "47 failed", status: "warning" },
  { name: "_postgres", uid: 70,  groups: "postgres",    shell: "/bin/bash", last_login: "6h ago",    status: "warning" },
];

export default function IdentityAccess() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [tab, setTab] = useState<"findings" | "accounts">("findings");

  const filtered = MOCK.filter(f =>
    (!severity || f.severity === severity) &&
    (!status   || f.status   === status)   &&
    (!search   || f.title.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div>
      <PageHeader
        icon={<Users className="w-6 h-6 text-[--indigo-600]" />}
        title="Identity & Access"
        subtitle="Account anomalies · privilege escalation · sudo grants · login patterns"
        backstory="74% of breaches involve the human element — either through compromised credentials, privilege abuse, or social engineering (Verizon DBIR 2024). On macOS, the three highest-confidence indicators of account compromise are: (1) new UID=0 account outside an installer workflow, (2) admin group membership changes outside business hours, and (3) service accounts with interactive shell logins. These map directly to MITRE ATT&CK techniques T1136 (Create Account), T1548 (Abuse Elevation Control), and T1078 (Valid Accounts)."
        accentClass="border-l-[--indigo-600]"
        bgClass="from-[--indigo-50]"
        tactics={["TA0003 · Persistence", "TA0004 · Privilege Escalation", "TA0006 · Credential Access"]}
        techniqueIds={[
          { id: "T1136.001", label: "Local Account" },
          { id: "T1548.003", label: "Sudo & Sudo Caching" },
          { id: "T1078",     label: "Valid Accounts" },
        ]}
        kpis={[
          { label: "UID=0 Anomalies",   value: 1, color: "red"    },
          { label: "Admin Changes",     value: 1, color: "red"    },
          { label: "Sudo Escalations",  value: 2, color: "amber"  },
          { label: "Login Anomalies",   value: 2, color: "amber"  },
        ]}
      />

      <div className="flex gap-1 mb-3">
        {(["findings", "accounts"] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors capitalize ${tab === t ? "bg-[--indigo-600] text-white" : "bg-white border border-[--gray-200] text-[--gray-600] hover:bg-[--gray-50]"}`}>
            {t === "accounts" ? "Account Registry" : "Findings"}
          </button>
        ))}
      </div>

      {tab === "findings" && (
        <>
          <FilterBar search={search} onSearch={setSearch} severity={severity} onSeverity={setSeverity} status={status} onStatus={setStatus} />
          <FindingsTable findings={filtered} />
        </>
      )}

      {tab === "accounts" && (
        <div className="space-y-3">
          <SectionHeading title="Local Account Inventory" count={ACCOUNTS.length} color="blue" />
          <div className="bg-white border border-[--gray-200] rounded-lg shadow-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-gradient-to-r from-[--gray-25] to-white border-b border-[--gray-200]">
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Account</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">UID</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Groups</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Shell</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Last Login</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Risk</th>
                </tr>
              </thead>
              <tbody>
                {ACCOUNTS.map(a => (
                  <tr key={a.name} className={`border-b border-[--gray-100] hover:bg-[--gray-25] ${a.status === "critical" ? "bg-[--red-50]/40" : ""}`}>
                    <td className="px-3 py-2.5 font-mono font-medium text-[--gray-800]">{a.name}</td>
                    <td className="px-3 py-2.5">
                      <span className={`font-bold ${a.uid === 0 ? "text-[--red-600]" : "text-[--gray-600]"}`}>{a.uid}</span>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[--gray-500] text-[10px]">{a.groups}</td>
                    <td className="px-3 py-2.5 font-mono text-[--gray-500] text-[10px]">{a.shell}</td>
                    <td className="px-3 py-2.5 text-[--gray-600]">{a.last_login}</td>
                    <td className="px-3 py-2.5">
                      {a.status === "critical" && <span className="px-2 py-0.5 bg-[--red-100] text-[--red-700] border border-[--red-600]/30 rounded text-[10px] font-bold">UID=0 ANOMALY</span>}
                      {a.status === "warning"  && <span className="px-2 py-0.5 bg-[--amber-50] text-[--amber-700] border border-[--amber-500]/20 rounded text-[10px] font-semibold">Review</span>}
                      {a.status === "ok"       && <span className="px-2 py-0.5 bg-[--green-50] text-[--green-700] border border-[--green-600]/20 rounded text-[10px] font-semibold">OK</span>}
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
