import { ShieldCheck } from "lucide-react";
import { PageHeader, SectionHeading } from "./shared";

interface Control {
  id: string;
  name: string;
  status: "pass" | "fail" | "warn";
  detail: string;
  mitre?: string;
  severity: "critical" | "high" | "medium" | "low";
}

const CONTROLS: Control[] = [
  { id: "SIP",  name: "System Integrity Protection", status: "fail", detail: "csrutil status = disabled. SIP prevents rootkits from modifying /System. Off = malware can persist at kernel level.", mitre: "T1553.001", severity: "critical" },
  { id: "FV2",  name: "FileVault 2 Full-Disk Encryption", status: "fail", detail: "fdesetup status = Off. Physical access grants complete disk read without password.", severity: "critical" },
  { id: "GK",   name: "Gatekeeper — Code Signing Enforcement", status: "warn", detail: "spctl --status = assessments disabled for third-party code. Unsigned binaries run without user warning.", mitre: "T1553.001", severity: "high" },
  { id: "FW",   name: "Application Firewall (PF)", status: "fail", detail: "Firewall disabled. All inbound connections accepted without filtering.", severity: "high" },
  { id: "XP",   name: "XProtect Malware Definitions", status: "pass", detail: "XProtect version 2192 — up to date. Covers 200+ malware families.", severity: "low" },
  { id: "AU",   name: "Automatic Security Updates", status: "warn", detail: "Automatic updates enabled but deferred for 90 days — 3 OS security patches pending.", severity: "medium" },
  { id: "SCR",  name: "Screen Lock / Password Timeout", status: "fail", detail: "Screensaver require password = Never. Physical access to unlocked machine.", severity: "high" },
  { id: "SSH",  name: "Remote Login (SSH) Service", status: "warn", detail: "SSH enabled and listening on port 22 (0.0.0.0). Exposed to local network.", mitre: "T1021.004", severity: "medium" },
  { id: "ARD",  name: "Apple Remote Desktop", status: "pass", detail: "Remote Management not enabled.", severity: "low" },
  { id: "SL",   name: "Secure Boot Level", status: "pass", detail: "boot-args = secure. Kernel extension signing enforced.", severity: "low" },
  { id: "TM",   name: "Time Machine Backup", status: "warn", detail: "Last backup 8 days ago. Recovery point objective exceeded.", severity: "low" },
];

const CIS_GROUPS = [
  { id: "CIS-1",  name: "Inventory & Control of Enterprise Assets",   pass: 3, fail: 1, total: 4 },
  { id: "CIS-2",  name: "Inventory & Control of Software Assets",     pass: 4, fail: 3, total: 7 },
  { id: "CIS-4",  name: "Secure Configuration of Enterprise Assets",  pass: 1, fail: 8, total: 9 },
  { id: "CIS-5",  name: "Account Management",                         pass: 2, fail: 3, total: 5 },
  { id: "CIS-6",  name: "Access Control Management",                  pass: 3, fail: 2, total: 5 },
  { id: "CIS-7",  name: "Continuous Vulnerability Management",        pass: 1, fail: 7, total: 8 },
  { id: "CIS-10", name: "Malware Defenses",                           pass: 3, fail: 1, total: 4 },
  { id: "CIS-12", name: "Network Infrastructure Management",          pass: 3, fail: 5, total: 8 },
];

export default function SecurityPosture() {
  const pass = CONTROLS.filter(c => c.status === "pass").length;
  const fail = CONTROLS.filter(c => c.status === "fail").length;
  const warn = CONTROLS.filter(c => c.status === "warn").length;
  const cisPass = CIS_GROUPS.reduce((a, g) => a + g.pass, 0);
  const cisTotal = CIS_GROUPS.reduce((a, g) => a + g.total, 0);

  const statusColor = (s: Control["status"]) =>
    s === "pass" ? "bg-[--green-50] text-[--green-700] border-[--green-600]/20"
    : s === "fail" ? "bg-[--red-50] text-[--red-600] border-[--red-600]/20"
    : "bg-[--amber-50] text-[--amber-700] border-[--amber-500]/20";

  const statusLabel = (s: Control["status"]) =>
    s === "pass" ? "PASS" : s === "fail" ? "FAIL" : "WARN";

  const barColor = (pct: number) =>
    pct >= 70 ? "bg-gradient-to-r from-[--green-500] to-[--green-600]"
    : pct >= 40 ? "bg-gradient-to-r from-[--amber-500] to-[--amber-600]"
    : "bg-gradient-to-r from-[--red-500] to-[--red-600]";

  return (
    <div>
      <PageHeader
        icon={<ShieldCheck className="w-6 h-6 text-[--green-600]" />}
        title="Security Posture"
        subtitle="macOS hardening controls · CIS Benchmark v8 · configuration drift"
        backstory="The CIS Controls v8 Benchmark defines the minimum hardening baseline for macOS endpoints. These aren't findings from active threats — they are the configuration of the attack surface itself. SIP disabled alone increases malware rootkit survival rate by 73%. FileVault off means any physical access = complete disk read. Gatekeeper off means unsigned code executes without warning. A single failed critical control multiplies the blast radius of every other finding on this machine. Fix these before tuning detection rules."
        accentClass="border-l-[--green-600]"
        bgClass="from-[--green-50]"
        tactics={["CIS Controls v8", "macOS Hardening Baseline"]}
        kpis={[
          { label: "Controls Failing", value: fail, color: "red"   },
          { label: "Warnings",         value: warn, color: "amber" },
          { label: "Passing",          value: pass, color: "green" },
          { label: `CIS Score (${cisPass}/${cisTotal})`, value: `${Math.round((cisPass/cisTotal)*100)}%`, color: cisPass/cisTotal > 0.7 ? "green" : "red" },
        ]}
      />

      <div className="grid grid-cols-[1fr_300px] gap-4">
        {/* Controls table */}
        <div>
          <SectionHeading title="macOS Security Controls" count={CONTROLS.length} color="green" />
          <div className="bg-white border border-[--gray-200] rounded-lg shadow-card overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-gradient-to-r from-[--gray-25] to-white border-b border-[--gray-200]">
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Control</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Status</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">Detail</th>
                  <th className="px-3 py-2 text-left text-[10px] font-semibold text-[--gray-500] uppercase tracking-wide">MITRE</th>
                </tr>
              </thead>
              <tbody>
                {CONTROLS.map(c => (
                  <tr key={c.id} className={`border-b border-[--gray-100] hover:bg-[--gray-25] ${c.status === "fail" ? "bg-[--red-50]/20" : ""}`}>
                    <td className="px-3 py-2.5">
                      <div className="font-medium text-[--gray-800]">{c.name}</div>
                      <div className="text-[10px] text-[--gray-400] font-mono">{c.id}</div>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`px-2 py-0.5 text-[10px] font-bold rounded border ${statusColor(c.status)}`}>
                        {statusLabel(c.status)}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 text-[--gray-600] max-w-xs">
                      <div className="line-clamp-2 leading-relaxed">{c.detail}</div>
                    </td>
                    <td className="px-3 py-2.5">
                      {c.mitre && (
                        <span className="px-1.5 py-0.5 bg-[--indigo-50] text-[--indigo-600] border border-[--indigo-600]/20 rounded text-[10px] font-mono">{c.mitre}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* CIS Benchmark scores */}
        <div>
          <SectionHeading title="CIS Benchmark v8" count={undefined} color="amber" />
          <div className="bg-white border border-[--gray-200] rounded-lg shadow-card p-4 space-y-3">
            <div className="text-center pb-3 border-b border-[--gray-100]">
              <div className={`text-3xl font-bold ${cisPass/cisTotal > 0.7 ? "text-[--green-600]" : "text-[--red-600]"}`}>
                {Math.round((cisPass/cisTotal)*100)}%
              </div>
              <div className="text-[10px] text-[--gray-500] mt-0.5">{cisPass} / {cisTotal} controls passing</div>
            </div>
            {CIS_GROUPS.map(g => {
              const pct = Math.round((g.pass / g.total) * 100);
              return (
                <div key={g.id}>
                  <div className="flex justify-between text-[10px] mb-1">
                    <span className="font-semibold text-[--gray-700]">{g.id}</span>
                    <span className={pct >= 70 ? "text-[--green-600]" : pct >= 40 ? "text-[--amber-600]" : "text-[--red-600]"}>
                      {g.pass}/{g.total}
                    </span>
                  </div>
                  <div className="w-full h-1.5 bg-[--gray-100] rounded-full mb-0.5">
                    <div className={`h-full rounded-full ${barColor(pct)}`} style={{ width: `${pct}%` }} />
                  </div>
                  <div className="text-[10px] text-[--gray-500]">{g.name}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
