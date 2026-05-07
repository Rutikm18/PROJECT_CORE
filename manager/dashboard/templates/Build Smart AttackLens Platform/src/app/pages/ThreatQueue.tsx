import { useState } from "react";
import { AlertTriangle, RefreshCw, UserCheck, X, CheckCircle, Flag } from "lucide-react";
import { PageHeader, FilterBar, FindingsTable, SevBadge, StatusBadge, type Finding } from "./shared";

const MOCK: Finding[] = [
  { id: 1,  title: "Cobalt Strike beacon detected", category: "process", severity: "critical", score: 9.7, mitre_technique: "T1071.001", mitre_tactic: "Command and Control", agent_id: "mac-a1b2", first_detected_at: 1746574800, last_detected_at: 1746621600, status: "new", description: "CobaltStrike process signature matched in rundll32-equivalent; 96-byte jitter-free beacon interval", kev: false, epss_score: 0.96 },
  { id: 2,  title: "Office application spawned bash shell", category: "process", severity: "critical", score: 9.4, mitre_technique: "T1566.001", mitre_tactic: "Initial Access", agent_id: "mac-a1b2", first_detected_at: 1746618000, last_detected_at: 1746621600, status: "triaging", description: "Microsoft Word (parent PID 4421) spawned /bin/bash (child PID 4478) — macro execution IoC", kev: false },
  { id: 3,  title: "CVE-2024-44308 — curl 7.86.0 (KEV)", category: "package", severity: "critical", score: 9.1, mitre_technique: "T1190", mitre_tactic: "Initial Access", agent_id: "mac-c3d4", first_detected_at: 1746532000, last_detected_at: 1746621600, status: "new", description: "curl 7.86.0 vulnerable to CVE-2024-44308 — CISA KEV listed, EPSS 94%, remote code exec", kev: true, epss_score: 0.94 },
  { id: 4,  title: "SIP (System Integrity Protection) disabled", category: "security", severity: "critical", score: 8.9, mitre_technique: "T1553.001", mitre_tactic: "Defense Evasion", agent_id: "mac-e5f6", first_detected_at: 1746580000, last_detected_at: 1746621600, status: "new", description: "csrutil status = disabled. SIP off increases malware rootkit survival rate by 73%.", kev: false },
  { id: 5,  title: "New LaunchDaemon registered outside business hours", category: "service", severity: "high", score: 8.4, mitre_technique: "T1543.004", mitre_tactic: "Persistence", agent_id: "mac-a1b2", first_detected_at: 1746599400, last_detected_at: 1746621600, status: "triaging", description: "com.update-helper.plist added at 02:14 local time — not matching any known software installer", kev: false },
  { id: 6,  title: "UID=0 account created without sudo", category: "user", severity: "high", score: 8.1, mitre_technique: "T1136.001", mitre_tactic: "Persistence", agent_id: "mac-c3d4", first_detected_at: 1746610200, last_detected_at: 1746621600, status: "new", description: "Account 'svc_backup' created with uid=0 directly — bypasses normal admin creation flow", kev: false },
  { id: 7,  title: "Beaconing to fixed IP set (entropy 0.8)", category: "connection", severity: "high", score: 7.9, mitre_technique: "T1071.001", mitre_tactic: "Command and Control", agent_id: "mac-a1b2", first_detected_at: 1746600000, last_detected_at: 1746621600, status: "investigating", description: "18 outbound connections to 3 IPs, entropy 0.8 < threshold 1.2; 30s ± 2s jitter — C2 beaconing candidate", kev: false },
  { id: 8,  title: "CVE-2023-32373 — openssl 3.1.2 (KEV)", category: "package", severity: "high", score: 7.7, mitre_technique: "T1190", mitre_tactic: "Initial Access", agent_id: "mac-e5f6", first_detected_at: 1746520000, last_detected_at: 1746621600, status: "triaging", description: "openssl 3.1.2 EPSS 87%, CISA KEV listed. Used actively in ransomware delivery chains Q1 2024.", kev: true, epss_score: 0.87 },
  { id: 9,  title: "nmap / port scanner spawned from cron", category: "process", severity: "high", score: 7.2, mitre_technique: "T1046", mitre_tactic: "Discovery", agent_id: "mac-g7h8", first_detected_at: 1746614400, last_detected_at: 1746621600, status: "new", description: "nmap binary executed by cron job com.backup.daily — not matching any known inventory package", kev: false },
  { id: 10, title: "FileVault full-disk encryption disabled", category: "security", severity: "medium", score: 6.5, mitre_technique: "T1486", mitre_tactic: "Impact", agent_id: "mac-g7h8", first_detected_at: 1746590000, last_detected_at: 1746621600, status: "in_remediation", description: "fdesetup status = Off. Physical access = complete disk read without password.", kev: false },
  { id: 11, title: "CPU velocity spike 4.1× above baseline", category: "behavioral", severity: "medium", score: 6.1, mitre_technique: "T1496", mitre_tactic: "Impact", agent_id: "mac-c3d4", first_detected_at: 1746617000, last_detected_at: 1746621600, status: "new", description: "CPU 4.1× above Welford baseline mean. No UI activity. Cryptomining or batch exfil candidate.", kev: false },
  { id: 12, title: "Gatekeeper disabled for third-party code", category: "security", severity: "medium", score: 5.8, mitre_technique: "T1553.001", mitre_tactic: "Defense Evasion", agent_id: "mac-e5f6", first_detected_at: 1746545000, last_detected_at: 1746621600, status: "triaging", description: "spctl --status = disabled. Unsigned code runs without any macOS warning dialog.", kev: false },
];

export default function ThreatQueue() {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [checked, setChecked] = useState<Set<number>>(new Set());

  const filtered = MOCK.filter(f =>
    (!severity || f.severity === severity) &&
    (!status   || f.status   === status)   &&
    (!search   || f.title.toLowerCase().includes(search.toLowerCase()))
  );

  const counts = {
    new:   MOCK.filter(f => f.status === "new").length,
    triage: MOCK.filter(f => f.status === "triaging").length,
    crit:  MOCK.filter(f => f.severity === "critical").length,
    unassigned: MOCK.filter(f => !f.assignee).length,
  };

  const toggleCheck = (id: number) => {
    setChecked(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  return (
    <div>
      <PageHeader
        icon={<AlertTriangle className="w-6 h-6 text-[--red-600]" />}
        title="Threat Queue"
        subtitle="Analyst triage inbox · prioritized by composite risk score"
        backstory="Studies show analysts spend 23% of their shift on alert triage (ESG 2023). A queue sorted by composite risk score — CVSS × EPSS × KEV × asset tier — instead of arrival time cuts mean-time-to-triage by 40%. Every finding here is ordered by how likely it is to represent real harm, not when it was detected. Work from the top down."
        accentClass="border-l-[--red-600]"
        bgClass="from-[--red-50]"
        tactics={["Triage Workflow", "SOC Operations"]}
        kpis={[
          { label: "New (unread)",    value: counts.new,       color: "red"   },
          { label: "Triaging",        value: counts.triage,    color: "amber" },
          { label: "Critical open",   value: counts.crit,      color: "red"   },
          { label: "Unassigned",      value: counts.unassigned,color: "amber" },
        ]}
        actions={
          <button className="flex items-center gap-1.5 px-3 py-1.5 bg-[--brand-orange] text-white text-xs font-semibold rounded-md hover:bg-[--brand-orange-700] transition-colors">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        }
      />

      {/* Bulk action bar */}
      {checked.size > 0 && (
        <div className="flex items-center gap-3 mb-3 px-3 py-2 bg-[--indigo-50] border border-[--indigo-600]/20 rounded-lg text-xs">
          <span className="font-semibold text-[--indigo-600]">{checked.size} selected</span>
          <button className="flex items-center gap-1 px-2 py-1 bg-white border border-[--gray-200] rounded text-[--gray-700] hover:bg-[--gray-50]">
            <UserCheck className="w-3 h-3" /> Assign to me
          </button>
          <button className="flex items-center gap-1 px-2 py-1 bg-white border border-[--gray-200] rounded text-[--gray-700] hover:bg-[--gray-50]">
            <CheckCircle className="w-3 h-3" /> Mark Triaging
          </button>
          <button className="flex items-center gap-1 px-2 py-1 bg-white border border-[--gray-200] rounded text-[--gray-700] hover:bg-[--gray-50]">
            <Flag className="w-3 h-3" /> False Positive
          </button>
          <button className="flex items-center gap-1 px-2 py-1 bg-[--red-50] border border-[--red-600]/20 rounded text-[--red-600] hover:bg-[--red-100]"
            onClick={() => setChecked(new Set())}>
            <X className="w-3 h-3" /> Clear
          </button>
        </div>
      )}

      <FilterBar
        search={search} onSearch={setSearch}
        severity={severity} onSeverity={setSeverity}
        status={status} onStatus={setStatus}
        extra={
          <select className="px-2 py-1.5 text-xs border border-[--gray-200] rounded-md bg-white text-[--gray-700]">
            <option>All Agents</option>
            <option>mac-a1b2</option>
            <option>mac-c3d4</option>
          </select>
        }
      />

      {/* Findings table with checkbox column */}
      <div className="bg-white border border-[--gray-200] rounded-lg shadow-card overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-gradient-to-r from-[--gray-25] to-white border-b border-[--gray-200]">
              <th className="px-3 py-2 w-8"></th>
              <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Finding</th>
              <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Score</th>
              <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">MITRE</th>
              <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Status</th>
              <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Intel</th>
              <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Agent</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(f => (
              <tr key={f.id}
                onClick={() => setSelected(f)}
                className={`border-b border-[--gray-100] hover:bg-[--gray-25] transition-colors cursor-pointer ${selected?.id === f.id ? "bg-[--brand-orange-50]" : ""}`}
              >
                <td className="px-3 py-2.5" onClick={e => { e.stopPropagation(); toggleCheck(f.id); }}>
                  <input type="checkbox" checked={checked.has(f.id)} onChange={() => {}} className="rounded border-[--gray-300]" />
                </td>
                <td className="px-3 py-2.5">
                  <div className="flex items-start gap-2">
                    <SevBadge sev={f.severity} />
                    <div>
                      <div className="font-medium text-[--gray-800]">{f.title}</div>
                      <div className="text-[--gray-500] text-[10px] mt-0.5 max-w-md truncate">{f.description}</div>
                    </div>
                  </div>
                </td>
                <td className="px-3 py-2.5">
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-1.5 bg-[--gray-100] rounded-full">
                      <div className={`h-full rounded-full ${f.score >= 8 ? "bg-gradient-to-r from-[--red-500] to-[--red-600]" : f.score >= 6 ? "bg-gradient-to-r from-[--amber-500] to-[--amber-600]" : "bg-gradient-to-r from-[--blue-500] to-[--blue-600]"}`}
                        style={{ width: `${(f.score / 10) * 100}%` }} />
                    </div>
                    <span className="font-bold text-[--gray-700] w-6">{f.score.toFixed(1)}</span>
                  </div>
                </td>
                <td className="px-3 py-2.5">
                  {f.mitre_technique && (
                    <span className="px-1.5 py-0.5 bg-[--indigo-50] text-[--indigo-600] border border-[--indigo-600]/20 rounded text-[10px] font-mono">
                      {f.mitre_technique}
                    </span>
                  )}
                </td>
                <td className="px-3 py-2.5"><StatusBadge status={f.status} /></td>
                <td className="px-3 py-2.5 text-[10px]">
                  {f.kev && <span className="px-1.5 py-0.5 bg-[--red-100] text-[--red-700] border border-[--red-600]/30 rounded font-bold mr-1">KEV</span>}
                  {f.epss_score !== undefined && <span className="text-[--amber-600] font-medium">EPSS {Math.round(f.epss_score * 100)}%</span>}
                </td>
                <td className="px-3 py-2.5 font-mono text-[--gray-500] text-[10px]">{f.agent_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Detail drawer */}
      {selected && (
        <div className="fixed right-0 top-0 h-full w-96 bg-white border-l border-[--gray-200] shadow-elevated z-50 overflow-y-auto">
          <div className="p-4 border-b border-[--gray-200] flex items-start justify-between">
            <div>
              <SevBadge sev={selected.severity} />
              <h2 className="text-sm font-bold text-[--gray-900] mt-1">{selected.title}</h2>
              <p className="text-xs text-[--gray-500] mt-0.5">{selected.agent_id} · {selected.category}</p>
            </div>
            <button onClick={() => setSelected(null)} className="p-1 hover:bg-[--gray-100] rounded transition-colors">
              <X className="w-4 h-4 text-[--gray-500]" />
            </button>
          </div>
          <div className="p-4 space-y-4">
            <div>
              <div className="text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide mb-1">Description</div>
              <p className="text-xs text-[--gray-700] leading-relaxed">{selected.description}</p>
            </div>
            {selected.mitre_technique && (
              <div>
                <div className="text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide mb-1">MITRE ATT&CK</div>
                <div className="flex gap-2">
                  <span className="px-1.5 py-0.5 bg-[--indigo-50] text-[--indigo-600] border border-[--indigo-600]/20 rounded text-[10px] font-mono">{selected.mitre_technique}</span>
                  <span className="text-xs text-[--gray-600]">{selected.mitre_tactic}</span>
                </div>
              </div>
            )}
            <div>
              <div className="text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide mb-1">Composite Score</div>
              <div className="text-2xl font-bold text-[--red-600]">{selected.score.toFixed(1)} <span className="text-sm font-normal text-[--gray-500]">/ 10</span></div>
            </div>
            <div className="flex gap-2 pt-2">
              <button className="flex-1 py-2 bg-[--brand-orange] text-white text-xs font-semibold rounded-md hover:bg-[--brand-orange-700] transition-colors">
                Assign to me
              </button>
              <button className="flex-1 py-2 bg-[--gray-100] text-[--gray-700] text-xs font-semibold rounded-md hover:bg-[--gray-200] transition-colors">
                Mark Triaging
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
