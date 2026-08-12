/**
 * MeshThreats — Mesh terrain (developer & AI-agent tooling attack surface).
 *
 * Surfaces incidents from the developer_security detection module (AL-DEV-00x):
 * editor extensions, MCP servers, CLI/PATH, browser & native messaging, git
 * overrides, credential exposure, listeners, dev containers.
 *
 * Structurally mirrors ExecutionThreats (Citadels). The one difference: every
 * finding shares category="developer_security", so the page sub-divides by
 * CAPABILITY (rule_id) instead of by category. Chip/KPI counts are computed
 * precisely from rule_id; a chip click filters the shared table via
 * initialSearch (each AL-DEV rule title contains its capability keyword).
 */
import { useState, useMemo, useEffect, type ReactNode } from "react";
import {
  Radio, CheckCircle2, AlertTriangle, Shield, Database,
  ExternalLink, KeyRound, Puzzle, Activity,
} from "lucide-react";
import {
  TerrainDetectionPage, useDetectionData, type DetectionFinding,
} from "./DetectionShared";
import { cn } from "../../lib/utils";

// ── Capability model (rule_id → capability) ─────────────────────────────────
export interface Capability {
  key: string; label: string; rules: string[]; search: string;
}
export const CAPABILITIES: Capability[] = [
  { key: "extension",  label: "Extensions",  rules: ["AL-DEV-001"],               search: "editor extension" },
  { key: "mcp",        label: "MCP",         rules: ["AL-DEV-002"],               search: "MCP server" },
  { key: "cli",        label: "CLI/PATH",    rules: ["AL-DEV-003"],               search: "search path" },
  { key: "browser",    label: "Browser",     rules: ["AL-DEV-004", "AL-DEV-005"], search: "messaging" },
  { key: "git",        label: "Git",         rules: ["AL-DEV-006"],               search: "Git execution" },
  { key: "credential", label: "Credentials", rules: ["AL-DEV-007"],               search: "Credential file" },
  { key: "listener",   label: "Listeners",   rules: ["AL-DEV-008"],               search: "listens on all" },
  { key: "runtime",    label: "Runtime",     rules: ["AL-DEV-009"],               search: "container" },
];

const RULE_TO_CAP: Record<string, Capability> = {};
for (const c of CAPABILITIES) for (const r of c.rules) RULE_TO_CAP[r] = c;

export function capabilityForRule(ruleId?: string): Capability | undefined {
  return ruleId ? RULE_TO_CAP[ruleId] : undefined;
}

export function countPartialHosts(
  rows?: { summary: { partial?: boolean } | null }[],
): number {
  if (!rows) return 0;
  return rows.filter(r => r.summary?.partial === true).length;
}

// ── Cell renderers ──────────────────────────────────────────────────────────
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

function CapabilityChipCell({ f }: { f: DetectionFinding }) {
  const cap = capabilityForRule(f.rule_id);
  return (
    <span className="text-[9px] font-semibold px-2 py-0.5 rounded-full border bg-violet-50 text-violet-700 border-violet-200">
      {cap?.label ?? "Developer"}
    </span>
  );
}

// ── KPI stat tile (identical pattern to ExecutionThreats) ───────────────────
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

type CapFilter = "all" | string;

// ── Main ────────────────────────────────────────────────────────────────────
export default function MeshThreats() {
  const [validatedOnly, setValidatedOnly] = useState(false);
  const [capFilter,     setCapFilter]     = useState<CapFilter>("all");

  const baseUrl = validatedOnly
    ? "/api/v1/detection/all?terrain_id=mesh&validated_only=true"
    : "/api/v1/detection/all?terrain_id=mesh";
  const statsUrl = `${baseUrl}&limit=500`;

  const { findings: raw } = useDetectionData(statsUrl);

  const [partialHosts, setPartialHosts] = useState(0);
  useEffect(() => {
    let dead = false;
    fetch("/api/v1/raw/query?section=developer_security&include_data=false&limit=50", { credentials: "include" })
      .then(r => (r.ok ? r.json() : Promise.reject(r.status)))
      .then((d: { rows?: { summary: { partial?: boolean } | null }[] }) => {
        if (!dead) setPartialHosts(countPartialHosts(d.rows));
      })
      .catch(() => { /* silent — badge simply won't show */ });
    return () => { dead = true; };
  }, []);

  const capCounts = useMemo(() => {
    const m: Record<string, number> = {};
    for (const c of CAPABILITIES) m[c.key] = raw.filter(f => c.rules.includes(f.rule_id ?? "")).length;
    return m;
  }, [raw]);

  const stats = useMemo(() => ({
    total:        raw.length,
    criticalHigh: raw.filter(f => f.severity === "critical" || f.severity === "high").length,
    agentTooling: (capCounts["mcp"] ?? 0) + (capCounts["extension"] ?? 0),
    credentials:  capCounts["credential"] ?? 0,
    listeners:    capCounts["listener"] ?? 0,
  }), [raw, capCounts]);

  const selectedCap = CAPABILITIES.find(c => c.key === capFilter);
  const pageKey = `${validatedOnly}:${capFilter}`;

  return (
    <div className="space-y-0 pb-6">
      {/* ── Domain header + KPIs ─────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 py-4">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-9 h-9 rounded-xl bg-violet-50 border border-violet-100 flex items-center justify-center flex-shrink-0">
            <Radio className="w-4.5 h-4.5" style={{ color: "#7C3AED" }} />
          </div>
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-bold text-gray-900">Mesh — Developer &amp; Agent Threats</h2>
            <p className="text-[10px] text-gray-400 mt-0.5">
              AI-tool &amp; coding-agent attack surface · extensions · MCP servers · CLI/PATH · browser · credentials · listeners
            </p>
          </div>
          <a
            href="https://attack.mitre.org/tactics/TA0002/"
            target="_blank" rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold bg-violet-50 border border-violet-200 text-violet-700 rounded-xl hover:bg-violet-100 transition-all flex-shrink-0"
          >
            <ExternalLink className="w-3 h-3" />MITRE ATT&amp;CK
          </a>
        </div>

        <div className="flex gap-2">
          <StatTile label="Mesh Incidents" value={stats.total} sub="total findings"
            icon={<Database className="w-3.5 h-3.5" />} valueClass="text-gray-800" />
          <StatTile label="Critical / High" value={stats.criticalHigh} sub="severity ≥ high"
            icon={<AlertTriangle className="w-3.5 h-3.5" />}
            valueClass={stats.criticalHigh > 0 ? "text-red-600" : "text-gray-600"}
            warn={stats.criticalHigh > 0} />
          <StatTile label="Agent Tooling" value={stats.agentTooling} sub="MCP + extensions"
            icon={<Puzzle className="w-3.5 h-3.5" />}
            valueClass={stats.agentTooling > 0 ? "text-violet-600" : "text-gray-600"} />
          <StatTile label="Credentials Exposed" value={stats.credentials} sub="secret file perms"
            icon={<KeyRound className="w-3.5 h-3.5" />}
            valueClass={stats.credentials > 0 ? "text-red-600" : "text-gray-600"}
            warn={stats.credentials > 0} />
          <StatTile label="Network Exposed" value={stats.listeners} sub="all-interface listeners"
            icon={<Activity className="w-3.5 h-3.5" />}
            valueClass={stats.listeners > 0 ? "text-orange-600" : "text-gray-600"} />
        </div>
      </div>

      {/* ── Partial-data banner ──────────────────────────────────────────── */}
      {partialHosts > 0 && (
        <div className="flex items-center gap-3 px-5 py-2 bg-amber-50 border-b border-amber-200">
          <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0" />
          <span className="text-[11px] text-amber-900 font-semibold">
            {partialHosts} {partialHosts === 1 ? "host" : "hosts"} reported truncated deep-mesh telemetry —
            some tooling was dropped at collection, so incident counts may be incomplete for those hosts.
          </span>
        </div>
      )}

      {/* ── Filter controls ──────────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 pt-4 pb-3 space-y-3">
        {/* Capability chips */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider whitespace-nowrap">Capability</span>
          <div className="flex items-center gap-1 flex-wrap">
            <button
              onClick={() => setCapFilter("all")}
              className={cn("flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                capFilter === "all" ? "bg-violet-600 text-white border-violet-600 shadow-sm"
                  : "bg-white text-gray-500 border-gray-200 hover:border-gray-300 hover:bg-gray-50")}
            >
              All
            </button>
            {CAPABILITIES.map(c => {
              const count = capCounts[c.key] ?? 0;
              if (count === 0) return null;
              return (
                <button
                  key={c.key}
                  onClick={() => setCapFilter(c.key)}
                  className={cn("flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                    capFilter === c.key ? "bg-violet-600 text-white border-violet-600 shadow-sm"
                      : "bg-white text-gray-500 border-gray-200 hover:border-gray-300 hover:bg-gray-50")}
                >
                  {c.label}
                  <span className={cn("ml-0.5 text-[8px] font-black px-1 rounded",
                    capFilter === c.key ? "bg-white/20 text-white" : "bg-gray-100 text-gray-600")}>
                    {count}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Validated toggle */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="inline-flex bg-gray-100 rounded-lg p-0.5">
            <button
              onClick={() => setValidatedOnly(false)}
              className={cn("px-3 py-1.5 rounded-md text-[10px] font-bold transition-all",
                !validatedOnly ? "bg-white text-violet-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
            >
              All Mesh
            </button>
            <button
              onClick={() => setValidatedOnly(true)}
              className={cn("flex items-center gap-1 px-3 py-1.5 rounded-md text-[10px] font-bold transition-all",
                validatedOnly ? "bg-white text-emerald-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
            >
              <CheckCircle2 className="w-3 h-3" />Validated
            </button>
          </div>

          {stats.credentials > 0 && (
            <div className="flex items-start gap-2.5 px-3 py-2 bg-red-50 border border-red-200 rounded-xl ml-auto">
              <Shield className="w-3.5 h-3.5 text-red-600 flex-shrink-0 mt-0.5" />
              <div className="text-[10px] text-red-900 leading-relaxed">
                <span className="font-bold">Playbook: </span>
                rotate any credential in an over-permissive file, then tighten perms to <code className="font-mono text-[9px] bg-red-100 px-1 rounded">600</code>.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Main detection table ─────────────────────────────────────────── */}
      <TerrainDetectionPage
        key={pageKey}
        apiUrl={baseUrl}
        accent="violet"
        emptyMsg={
          validatedOnly
            ? "No validated findings in Mesh."
            : "No developer/agent-tooling findings yet. Findings appear when the developer_security collector reports a risky component."
        }
        initialSearch={selectedCap?.search}
        columns={[
          { key: "rule_id",         label: "Capability", render: f => <CapabilityChipCell f={f} /> },
          { key: "confidence_pct",  label: "Confidence", render: f => <ConfPct f={f} /> },
          { key: "composite_score", label: "Risk",       render: f => <RiskScore f={f} /> },
          { key: "mitre_technique", label: "MITRE",      render: f => <span className="text-[9px] font-mono text-gray-400 truncate max-w-[80px] block">{f.mitre_technique ?? "—"}</span> },
        ]}
      />
    </div>
  );
}
