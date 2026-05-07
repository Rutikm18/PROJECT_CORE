import { BarChart3 } from "lucide-react";
import { PageHeader, SectionHeading, SevBadge } from "./shared";

const DAILY = [
  { date: "Apr 30", critical: 2, high: 5, medium: 8,  total: 15, remediated: 4  },
  { date: "May 1",  critical: 1, high: 3, medium: 6,  total: 10, remediated: 8  },
  { date: "May 2",  critical: 4, high: 7, medium: 9,  total: 20, remediated: 3  },
  { date: "May 3",  critical: 3, high: 6, medium: 11, total: 20, remediated: 7  },
  { date: "May 4",  critical: 2, high: 4, medium: 7,  total: 13, remediated: 12 },
  { date: "May 5",  critical: 5, high: 8, medium: 10, total: 23, remediated: 5  },
  { date: "May 6",  critical: 7, high: 12,medium: 14, total: 33, remediated: 2  },
];

const MTTR = [
  { severity: "Critical", target_h: 4,  actual_h: 9.2, status: "BREACHED" },
  { severity: "High",     target_h: 24, actual_h: 18.4,status: "ON TRACK" },
  { severity: "Medium",   target_h: 168,actual_h: 42.1,status: "ON TRACK" },
  { severity: "Low",      target_h: 720,actual_h: 96.3,status: "ON TRACK" },
];

const RECENT_EVENTS = [
  { time: "14:37", type: "critical",   msg: "Cobalt Strike beacon detected — mac-a1b2",          action: "auto-escalated" },
  { time: "14:02", type: "high",       msg: "LaunchDaemon com.update-helper added — mac-a1b2",    action: "assigned: analyst1" },
  { time: "13:51", type: "info",       msg: "Threat feed sync complete — 5 feeds, 590K IOCs",     action: "system" },
  { time: "12:44", type: "high",       msg: "CVE-2024-44308 detected — mac-c3d4",                 action: "new" },
  { time: "11:30", type: "remediated", msg: "CVE-2023-5678 marked remediated — mac-e5f6",         action: "closed by analyst2" },
  { time: "10:18", type: "critical",   msg: "UID=0 account 'svc_backup' created — mac-c3d4",      action: "escalated to incident" },
  { time: "09:52", type: "info",       msg: "Agent mac-g7h8 enrolled",                            action: "enrollment" },
  { time: "09:14", type: "critical",   msg: "Word.app → bash → curl C2 chain detected — mac-a1b2",action: "auto-escalated" },
];

const maxTotal = Math.max(...DAILY.map(d => d.total));

export default function Timeline() {
  return (
    <div>
      <PageHeader
        icon={<BarChart3 className="w-6 h-6 text-[--blue-600]" />}
        title="Timeline & History"
        subtitle="Finding trends · MTTR tracking · 7-day activity · remediation cadence"
        backstory="The IBM Cost of a Data Breach 2024 report found that organizations with AI-driven detection and automation reduced breach costs by $2.22M compared to those without. Mean Time To Remediate (MTTR) is the primary SOC performance metric — faster detection + faster remediation = lower blast radius. Your timeline shows whether your security program is improving week-over-week. A rising critical finding count with flat remediation is the warning sign to escalate to CISO."
        accentClass="border-l-[--blue-600]"
        bgClass="from-[--blue-50]"
        tactics={["SOC Performance", "MTTR Tracking"]}
        kpis={[
          { label: "New (7d)",       value: DAILY.reduce((a, d) => a + d.total, 0),     color: "amber" },
          { label: "Remediated (7d)",value: DAILY.reduce((a, d) => a + d.remediated, 0),color: "green" },
          { label: "MTTR Critical",  value: "9.2h",                                      color: "red"   },
          { label: "SLA Breach",     value: "Critical",                                   color: "red"   },
        ]}
      />

      <div className="grid grid-cols-[1fr_280px] gap-4 mb-4">
        {/* Bar chart */}
        <div className="bg-white border border-[--gray-200] rounded-lg shadow-card p-4">
          <div className="text-xs font-bold text-[--gray-700] mb-4">Daily Finding Volume — 7 Days</div>
          <div className="flex items-end gap-2 h-40">
            {DAILY.map(d => (
              <div key={d.date} className="flex-1 flex flex-col items-center gap-1">
                <div className="w-full flex flex-col justify-end gap-0.5" style={{ height: "120px" }}>
                  <div className="w-full bg-[--red-500] rounded-sm opacity-90" style={{ height: `${(d.critical / maxTotal) * 100}px` }} title={`Critical: ${d.critical}`} />
                  <div className="w-full bg-[--amber-500] rounded-sm opacity-90" style={{ height: `${(d.high / maxTotal) * 100}px` }} />
                  <div className="w-full bg-[--blue-400] rounded-sm opacity-70" style={{ height: `${(d.medium / maxTotal) * 100}px` }} />
                </div>
                <div className="text-[9px] text-[--gray-400] text-center">{d.date}</div>
                <div className="text-[9px] font-bold text-[--gray-600]">{d.total}</div>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-4 mt-2 text-[10px] text-[--gray-500]">
            <span className="flex items-center gap-1"><span className="w-2 h-2 bg-[--red-500] rounded-sm inline-block" />Critical</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 bg-[--amber-500] rounded-sm inline-block" />High</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 bg-[--blue-400] rounded-sm inline-block" />Medium</span>
          </div>
        </div>

        {/* MTTR */}
        <div className="bg-white border border-[--gray-200] rounded-lg shadow-card p-4">
          <div className="text-xs font-bold text-[--gray-700] mb-3">Mean Time To Remediate</div>
          <div className="space-y-3">
            {MTTR.map(m => (
              <div key={m.severity}>
                <div className="flex justify-between text-[10px] mb-1">
                  <span className="font-semibold text-[--gray-700]">{m.severity}</span>
                  <span className={m.status === "BREACHED" ? "text-[--red-600] font-bold" : "text-[--green-600] font-semibold"}>
                    {m.actual_h}h
                  </span>
                </div>
                <div className="w-full h-1.5 bg-[--gray-100] rounded-full">
                  <div
                    className={`h-full rounded-full ${m.status === "BREACHED" ? "bg-gradient-to-r from-[--red-500] to-[--red-600]" : "bg-gradient-to-r from-[--green-500] to-[--green-600]"}`}
                    style={{ width: `${Math.min(100, (m.target_h / m.actual_h) * 60)}%` }}
                  />
                </div>
                <div className="text-[9px] text-[--gray-400] mt-0.5">Target: {m.target_h}h · <span className={m.status === "BREACHED" ? "text-[--red-600] font-bold" : "text-[--green-600]"}>{m.status}</span></div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Activity log */}
      <SectionHeading title="Activity Log — Today" color="gray" />
      <div className="bg-white border border-[--gray-200] rounded-lg shadow-card overflow-hidden">
        {RECENT_EVENTS.map((e, i) => (
          <div key={i} className="flex items-start gap-3 px-4 py-2.5 border-b border-[--gray-100] last:border-0 hover:bg-[--gray-25]">
            <span className="text-[10px] font-mono text-[--gray-400] w-10 flex-shrink-0 mt-0.5">{e.time}</span>
            <div className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${
              e.type === "critical" ? "bg-[--red-500]" :
              e.type === "high"     ? "bg-[--amber-500]" :
              e.type === "remediated" ? "bg-[--green-500]" : "bg-[--gray-300]"
            }`} />
            <span className="text-xs text-[--gray-700] flex-1">{e.msg}</span>
            <span className="text-[10px] text-[--gray-400] flex-shrink-0">{e.action}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
