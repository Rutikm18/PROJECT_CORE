/**
 * ExecutionThreats — Citadels terrain (process execution & malware).
 *
 * Domain context:
 *   Monitors process ancestry chains, binary metadata, and execution context
 *   for signs of LOLBin abuse, memory-only execution, privilege escalation,
 *   lateral movement, and persistence mechanisms.
 *
 * Attack terrain: Citadels — the execution layer where an adversary runs
 * code after initial access, establishing persistence and privilege escalation.
 */
import { useState, useMemo, type ReactNode } from "react";
import {
  Terminal, CheckCircle2, AlertTriangle, Shield, Zap,
  Database, ExternalLink, Cpu, GitBranch, Activity,
  Copy, Check, FileCode, Radio,
} from "lucide-react";
import {
  TerrainDetectionPage, useDetectionData, type DetectionFinding,
} from "./DetectionShared";
import { cn } from "../../lib/utils";

// ── Cell renderers ────────────────────────────────────────────────────────────

function RiskScore({ f }: { f: DetectionFinding }) {
  const s   = f.composite_score ?? f.score;
  const cls = s >= 8 ? "text-red-600 bg-red-50 border-red-200"
              : s >= 6 ? "text-amber-600 bg-amber-50 border-amber-200"
              :          "text-blue-600 bg-blue-50 border-blue-200";
  return (
    <div className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-black tabular-nums", cls)}>
      {s.toFixed(1)}<span className="text-[8px] font-normal opacity-60">/10</span>
    </div>
  );
}

function ConfPct({ f }: { f: DetectionFinding }) {
  const pct   = f.confidence_pct ?? 70;
  const color = pct >= 85 ? "text-green-600" : pct >= 70 ? "text-blue-600" : "text-amber-600";
  return <span className={cn("text-[10px] font-bold tabular-nums", color)}>{pct}%</span>;
}

function CategoryChip({ f }: { f: DetectionFinding }) {
  const COLORS: Record<string, string> = {
    malware:     "bg-red-50 text-red-700 border-red-200",
    execution:   "bg-orange-50 text-orange-700 border-orange-200",
    script:      "bg-purple-50 text-purple-700 border-purple-200",
    process:     "bg-blue-50 text-blue-700 border-blue-200",
    container:   "bg-teal-50 text-teal-700 border-teal-200",
    task:        "bg-amber-50 text-amber-700 border-amber-200",
    persistence: "bg-rose-50 text-rose-700 border-rose-200",
    service:     "bg-indigo-50 text-indigo-700 border-indigo-200",
    lateral:     "bg-pink-50 text-pink-700 border-pink-200",
    covert:      "bg-gray-50 text-gray-700 border-gray-300",
  };
  const cat = f.category?.toLowerCase() ?? "";
  const key = Object.keys(COLORS).find(k => cat.includes(k)) ?? "process";
  return (
    <span className={cn("text-[9px] font-semibold px-2 py-0.5 rounded-full border", COLORS[key])}>
      {f.category}
    </span>
  );
}

// ── KPI stat tile ─────────────────────────────────────────────────────────────

function StatTile({
  label, value, sub, icon, valueClass, warn = false,
}: {
  label: string; value: string | number; sub?: string;
  icon: ReactNode; valueClass: string; warn?: boolean;
}) {
  return (
    <div className={cn(
      "flex-1 rounded-xl border px-4 py-3 transition-all",
      warn ? "bg-red-50 border-red-200 shadow-sm" : "bg-white border-gray-100"
    )}>
      <div className={cn("mb-1 opacity-60", warn ? "text-red-500" : "text-gray-400")}>{icon}</div>
      <div className={cn("text-xl font-black tabular-nums leading-none", valueClass)}>{value}</div>
      {sub && <div className="text-[9px] text-gray-400 mt-0.5 font-medium">{sub}</div>}
      <div className="text-[10px] text-gray-500 font-semibold mt-1">{label}</div>
    </div>
  );
}

// ── Sigma rule copy helper ────────────────────────────────────────────────────

function CopySigmaButton({ category }: { category: string }) {
  const [copied, setCopied] = useState(false);
  const sigma = `title: Suspicious ${category} Detected by AttackLens
status: experimental
description: Detects ${category} patterns identified by AttackLens Citadels terrain
logsource:
  category: process_creation
  product: macos
detection:
  selection:
    EventID: 4688
    # Adjust to match specific process patterns from the finding
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059`;

  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(sigma); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold bg-white border border-gray-200 text-gray-600 rounded-xl hover:border-red-300 hover:text-red-700 hover:bg-red-50 transition-all"
    >
      {copied ? <Check className="w-3 h-3 text-green-500" /> : <FileCode className="w-3 h-3" />}
      {copied ? "Sigma Copied!" : "Copy Sigma Rule"}
    </button>
  );
}

// ── Types ─────────────────────────────────────────────────────────────────────

type CatFilter = "all" | "malware" | "execution" | "script" | "process" | "container" | "task" | "lateral";

const CAT_TABS: { key: CatFilter; label: string; color: string }[] = [
  { key: "all",       label: "All",       color: "gray"   },
  { key: "malware",   label: "Malware",   color: "red"    },
  { key: "execution", label: "Execution", color: "orange" },
  { key: "script",    label: "Scripts",   color: "purple" },
  { key: "process",   label: "Processes", color: "blue"   },
  { key: "container", label: "Container", color: "teal"   },
  { key: "task",      label: "Task",      color: "amber"  },
  { key: "lateral",   label: "Lateral",   color: "pink"   },
];

// ── Main ──────────────────────────────────────────────────────────────────────

export default function ExecutionThreats() {
  const [validatedOnly, setValidatedOnly] = useState(false);
  const [catFilter,     setCatFilter]     = useState<CatFilter>("all");
  const [kevOnly,       setKevOnly]       = useState(false);
  const [exploitOnly,   setExploitOnly]   = useState(false);

  // Build base API URL
  const baseUrl = validatedOnly
    ? "/api/v1/detection/all?terrain_id=citadels&validated_only=true"
    : "/api/v1/detection/all?terrain_id=citadels";
  const statsUrl = `${baseUrl}${baseUrl.includes("?") ? "&" : "?"}limit=500`;

  // Fetch for domain KPIs
  const { findings: raw } = useDetectionData(statsUrl);

  const stats = useMemo(() => {
    const cat = (f: DetectionFinding) => (f.category ?? "").toLowerCase();
    return {
      total:     raw.length,
      malware:   raw.filter(f => cat(f).includes("malware")).length,
      scripts:   raw.filter(f => cat(f).includes("script")).length,
      lateral:   raw.filter(f => cat(f).includes("lateral") || cat(f).includes("covert")).length,
      exploit:   raw.filter(f => f.exploit_available).length,
      highRisk:  raw.filter(f => (f.composite_score ?? f.score) >= 8).length,
      kev:       raw.filter(f => f.kev).length,
    };
  }, [raw]);

  const hasMalware = stats.malware > 0;

  const pageKey = `${validatedOnly}:${catFilter}:${kevOnly}:${exploitOnly}`;

  return (
    <div className="space-y-0 pb-6">

      {/* ── Alert strip ───────────────────────────────────────────────────────── */}
      {hasMalware && (
        <div className="flex items-center gap-3 px-5 py-2.5 bg-red-700">
          <AlertTriangle className="w-4 h-4 text-white flex-shrink-0 al-heartbeat" />
          <span className="text-[11px] text-white font-bold">
            {stats.malware} malware {stats.malware === 1 ? "detection" : "detections"} require immediate investigation and containment.
          </span>
          <a
            href="https://attack.mitre.org/tactics/TA0002/"
            target="_blank" rel="noopener noreferrer"
            className="ml-auto flex items-center gap-1 text-[10px] text-red-200 hover:text-white font-semibold transition-colors flex-shrink-0"
          >
            MITRE TA0002 <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      )}

      {/* ── Domain header + KPIs ─────────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 py-4">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-9 h-9 rounded-xl bg-red-50 border border-red-100 flex items-center justify-center flex-shrink-0">
            <Terminal className="w-4.5 h-4.5 text-red-600" />
          </div>
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-bold text-gray-900">Citadels — Execution Threats</h2>
            <p className="text-[10px] text-gray-400 mt-0.5">
              Process anomalies · malware detection · LOLBin abuse · privilege escalation · lateral movement · persistence
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <CopySigmaButton category={catFilter !== "all" ? catFilter : "execution"} />
            <a
              href="https://attack.mitre.org/tactics/TA0002/"
              target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold bg-red-50 border border-red-200 text-red-700 rounded-xl hover:bg-red-100 transition-all"
            >
              <ExternalLink className="w-3 h-3" />MITRE ATT&amp;CK
            </a>
          </div>
        </div>

        {/* KPI row */}
        <div className="flex gap-2">
          <StatTile
            label="Execution Threats" value={stats.total} sub="total findings"
            icon={<Database className="w-3.5 h-3.5" />}
            valueClass="text-gray-800"
          />
          <StatTile
            label="Malware Detected" value={stats.malware} sub="confirmed malware"
            icon={<AlertTriangle className="w-3.5 h-3.5" />}
            valueClass={stats.malware > 0 ? "text-red-600" : "text-gray-600"}
            warn={stats.malware > 0}
          />
          <StatTile
            label="Script Anomalies" value={stats.scripts} sub="suspicious scripts"
            icon={<FileCode className="w-3.5 h-3.5" />}
            valueClass={stats.scripts > 0 ? "text-purple-600" : "text-gray-600"}
          />
          <StatTile
            label="Lateral Movement" value={stats.lateral} sub="covert/lateral activity"
            icon={<GitBranch className="w-3.5 h-3.5" />}
            valueClass={stats.lateral > 0 ? "text-pink-600" : "text-gray-600"}
            warn={stats.lateral > 0}
          />
          <StatTile
            label="High Risk" value={stats.highRisk} sub="risk score ≥8.0"
            icon={<Activity className="w-3.5 h-3.5" />}
            valueClass={stats.highRisk > 0 ? "text-orange-600" : "text-gray-600"}
          />
        </div>
      </div>

      {/* ── Filter controls ───────────────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 pt-4 pb-3 space-y-3">

        {/* Row 1 — Category chips */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider whitespace-nowrap">Category</span>
          <div className="flex items-center gap-1 flex-wrap">
            {CAT_TABS.map(c => {
              // Count matching findings for each category chip
              const count = c.key === "all"
                ? raw.length
                : raw.filter(f => (f.category ?? "").toLowerCase().includes(c.key)).length;
              if (c.key !== "all" && count === 0) return null;
              return (
                <button
                  key={c.key}
                  onClick={() => setCatFilter(c.key)}
                  className={cn(
                    "flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                    catFilter === c.key
                      ? c.key === "malware" ? "bg-red-600 text-white border-red-600 shadow-sm"
                        : c.key === "script" ? "bg-purple-600 text-white border-purple-600 shadow-sm"
                        : c.key === "lateral" ? "bg-pink-600 text-white border-pink-600 shadow-sm"
                        : "bg-orange-500 text-white border-orange-500 shadow-sm"
                      : "bg-white text-gray-500 border-gray-200 hover:border-gray-300 hover:bg-gray-50"
                  )}
                >
                  {c.label}
                  {count > 0 && c.key !== "all" && (
                    <span className={cn(
                      "ml-0.5 text-[8px] font-black px-1 rounded",
                      catFilter === c.key ? "bg-white/20 text-white" : "bg-gray-100 text-gray-600"
                    )}>
                      {count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Row 2 — Validated + quick toggles */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Validated toggle */}
          <div className="inline-flex bg-gray-100 rounded-lg p-0.5">
            <button
              onClick={() => setValidatedOnly(false)}
              className={cn("px-3 py-1.5 rounded-md text-[10px] font-bold transition-all", !validatedOnly ? "bg-white text-red-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
            >
              All Citadels
            </button>
            <button
              onClick={() => setValidatedOnly(true)}
              className={cn("flex items-center gap-1 px-3 py-1.5 rounded-md text-[10px] font-bold transition-all", validatedOnly ? "bg-white text-emerald-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
            >
              <CheckCircle2 className="w-3 h-3" />Validated
            </button>
          </div>

          {/* KEV Only */}
          <button
            onClick={() => setKevOnly(v => !v)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-[10px] font-bold transition-all",
              kevOnly
                ? "bg-amber-500 text-white border-amber-500 shadow-sm"
                : "bg-white text-gray-600 border-gray-200 hover:border-amber-300 hover:text-amber-600 hover:bg-amber-50"
            )}
          >
            <Radio className={cn("w-3 h-3", kevOnly && "animate-pulse")} />KEV Only
            {stats.kev > 0 && (
              <span className={cn("ml-0.5 text-[8px] font-black px-1 rounded", kevOnly ? "bg-amber-400 text-white" : "bg-amber-100 text-amber-700")}>
                {stats.kev}
              </span>
            )}
          </button>

          {/* Exploit Only */}
          <button
            onClick={() => setExploitOnly(v => !v)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-[10px] font-bold transition-all",
              exploitOnly
                ? "bg-red-600 text-white border-red-600 shadow-sm"
                : "bg-white text-gray-600 border-gray-200 hover:border-red-300 hover:text-red-600 hover:bg-red-50"
            )}
          >
            <Zap className="w-3 h-3" />Exploit Only
            {stats.exploit > 0 && (
              <span className={cn("ml-0.5 text-[8px] font-black px-1 rounded", exploitOnly ? "bg-red-500 text-white" : "bg-red-100 text-red-700")}>
                {stats.exploit}
              </span>
            )}
          </button>

          {validatedOnly && (
            <span className="ml-auto text-[9px] text-emerald-700 font-semibold flex items-center gap-1 bg-emerald-50 px-2 py-1 rounded border border-emerald-200">
              <CheckCircle2 className="w-3 h-3" />precision_score ≥ threshold
            </span>
          )}
        </div>

        {/* Playbook hint */}
        {(hasMalware || stats.lateral > 0) && (
          <div className="flex items-start gap-2.5 px-3 py-2.5 bg-red-50 border border-red-200 rounded-xl">
            <Shield className="w-3.5 h-3.5 text-red-600 flex-shrink-0 mt-0.5" />
            <div className="text-[10px] text-red-900 leading-relaxed">
              <span className="font-bold">Containment playbook: </span>
              Isolate affected endpoint from network, capture memory dump (
              <code className="font-mono text-[9px] bg-red-100 px-1 rounded">osxpmem</code>),
              collect process ancestry via{" "}
              <code className="font-mono text-[9px] bg-red-100 px-1 rounded">ps -axo pid,ppid,comm,args</code>,
              hash suspicious binary and query VirusTotal before killing — preserves forensic chain.
            </div>
          </div>
        )}
      </div>

      {/* ── Main detection table ──────────────────────────────────────────────── */}
      <TerrainDetectionPage
        key={pageKey}
        apiUrl={baseUrl}
        accent="red"
        emptyMsg={
          validatedOnly
            ? "No validated findings in Citadels."
            : "No execution threat findings yet. Findings appear when agent processes match detection rules."
        }
        initialKevOnly={kevOnly}
        initialExploitOnly={exploitOnly}
        initialCategoryFilter={catFilter !== "all" ? catFilter : undefined}
        columns={[
          { key: "category",        label: "Category",   render: f => <CategoryChip f={f} /> },
          { key: "confidence_pct",  label: "Confidence", render: f => <ConfPct f={f} /> },
          { key: "composite_score", label: "Risk",       render: f => <RiskScore f={f} /> },
          { key: "source",          label: "Rule",       render: f => <span className="text-[9px] font-mono text-gray-400 truncate max-w-[80px] block">{f.source}</span> },
        ]}
      />
    </div>
  );
}
