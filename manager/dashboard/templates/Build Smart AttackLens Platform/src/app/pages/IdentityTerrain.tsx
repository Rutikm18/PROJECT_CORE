/**
 * IdentityTerrain — Identity terrain (accounts, privileges & credentials).
 *
 * Surfaces every finding the backend classifies as terrain_id="identity":
 * the engine's `user` analyzer (UID 0 clones, service accounts with
 * interactive shells) plus behavioural account anomalies that
 * terrain_validators routes here by metric (admin / user / login).
 *
 * Structurally mirrors MeshThreats: the terrain has only a couple of raw
 * categories, so the page sub-divides by SIGNAL (the emitting rule's `source`)
 * rather than by category. Chip counts are computed precisely from `source`;
 * clicking a chip filters the shared table via initialSearch, matching a
 * distinctive phrase from that rule's title.
 *
 * The signal list is deliberately aligned with IDENTITY_CRITERIA in
 * manager/manager/attacklens/terrain_validators.py — what the page highlights
 * is what the validator actually scores.
 */
import { useState, useMemo, type ReactNode } from "react";
import {
  ShieldCheck, CheckCircle2, AlertTriangle, Shield, Database,
  ExternalLink, KeyRound, UserPlus, Terminal,
} from "lucide-react";
import {
  TerrainDetectionPage, useDetectionData, type DetectionFinding,
} from "./DetectionShared";
import { cn } from "../../lib/utils";

// ── Signal model (source → signal) ──────────────────────────────────────────
//
// Two emitters produce identity findings and they use different rule names:
//
//   detections/user_account (the ROUTED path — what actually runs, because
//     ENGINE_CONFIG["use_detection_modules"] defaults to True)
//       uid_zero_clone · service_with_shell · privgroup_added · new_account ·
//       hidden_user · home_changed · shell_changed
//   engine._users (inline fallback)
//       rule:uid0 · rule:svc_interactive_shell
//   behavioral.py (cross-cutting, routed to identity by metric)
//       behavioral_change · behavioral_new_entity · behavioral_zscore
//
// Each signal claims every spelling of the same thing, so a chip counts the
// same on a module-routed deployment and an inline one. `search` is a
// full-text query over title + description + evidence, so the term is chosen
// to appear in BOTH emitters' wording rather than matching one title exactly.
export interface IdentitySignal {
  key: string; label: string; sources: string[]; search: string;
}

export const IDENTITY_SIGNALS: IdentitySignal[] = [
  { key: "uid0",        label: "Root-Equivalent", search: "root-equivalent",
    sources: ["uid_zero_clone", "rule:uid0"] },
  { key: "svc_shell",   label: "Service Shells",  search: "interactive shell",
    sources: ["service_with_shell", "rule:svc_interactive_shell", "shell_changed"] },
  { key: "admin_grant", label: "Privilege Granted", search: "privileged",
    sources: ["privgroup_added", "behavioral_change"] },
  { key: "new_account", label: "New Accounts",    search: "account",
    sources: ["new_account", "behavioral_new_entity"] },
  { key: "hidden",      label: "Hidden / Moved",  search: "hidden",
    sources: ["hidden_user", "home_changed"] },
  { key: "admin_spike", label: "Admin Spike",     search: "Admin user count",
    sources: ["behavioral_zscore"] },
];

const SOURCE_TO_SIGNAL: Record<string, IdentitySignal> = {};
for (const s of IDENTITY_SIGNALS) for (const src of s.sources) SOURCE_TO_SIGNAL[src] = s;

export function signalForSource(source?: string): IdentitySignal | undefined {
  return source ? SOURCE_TO_SIGNAL[source] : undefined;
}

/**
 * Count findings per signal key. Exported so the mapping stays under test —
 * a renamed rule `source` in the engine silently zeroes a chip otherwise.
 */
export function countIdentitySignals(
  findings: { source?: string }[],
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const s of IDENTITY_SIGNALS) counts[s.key] = 0;
  for (const f of findings) {
    const signal = signalForSource(f.source);
    if (signal) counts[signal.key] += 1;
  }
  return counts;
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

function SignalChipCell({ f }: { f: DetectionFinding }) {
  const signal = signalForSource(f.source);
  return (
    <span className="text-[9px] font-semibold px-2 py-0.5 rounded-full border bg-blue-50 text-blue-700 border-blue-200">
      {signal?.label ?? "Account"}
    </span>
  );
}

// ── KPI stat tile (identical pattern to MeshThreats / ExecutionThreats) ─────
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

type SignalFilter = "all" | string;

// ── Main ────────────────────────────────────────────────────────────────────
export default function IdentityTerrain() {
  const [validatedOnly,  setValidatedOnly]  = useState(false);
  const [signalFilter,   setSignalFilter]   = useState<SignalFilter>("all");

  const baseUrl = validatedOnly
    ? "/api/v1/detection/all?terrain_id=identity&validated_only=true"
    : "/api/v1/detection/all?terrain_id=identity";
  const statsUrl = `${baseUrl}&limit=500`;

  const { findings: raw } = useDetectionData(statsUrl);

  const signalCounts = useMemo(() => countIdentitySignals(raw), [raw]);

  const stats = useMemo(() => ({
    total:        raw.length,
    criticalHigh: raw.filter(f => f.severity === "critical" || f.severity === "high").length,
    rootEquiv:    signalCounts["uid0"] ?? 0,
    svcShells:    signalCounts["svc_shell"] ?? 0,
    privChange:   (signalCounts["admin_grant"] ?? 0) + (signalCounts["admin_spike"] ?? 0),
  }), [raw, signalCounts]);

  const selectedSignal = IDENTITY_SIGNALS.find(s => s.key === signalFilter);
  const pageKey = `${validatedOnly}:${signalFilter}`;
  const hasRootEquiv = stats.rootEquiv > 0;

  return (
    <div className="space-y-0 pb-6">

      {/* ── Alert strip — a non-root UID 0 is a definitive TP (anchor criterion) ── */}
      {hasRootEquiv && (
        <div className="flex items-center gap-3 px-5 py-2.5 bg-red-700">
          <AlertTriangle className="w-4 h-4 text-white flex-shrink-0 al-heartbeat" />
          <span className="text-[11px] text-white font-bold">
            {stats.rootEquiv} root-equivalent {stats.rootEquiv === 1 ? "account" : "accounts"} detected —
            a non-root UID 0 is a classic backdoor admin and needs immediate review.
          </span>
          <a
            href="https://attack.mitre.org/techniques/T1078/003/"
            target="_blank" rel="noopener noreferrer"
            className="ml-auto flex items-center gap-1 text-[10px] text-red-200 hover:text-white font-semibold transition-colors flex-shrink-0"
          >
            MITRE T1078.003 <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      )}

      {/* ── Domain header + KPIs ─────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 py-4">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-9 h-9 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center flex-shrink-0">
            <ShieldCheck className="w-4.5 h-4.5" style={{ color: "#3B82F6" }} />
          </div>
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-bold text-gray-900">Identity — Accounts &amp; Credentials</h2>
            <p className="text-[10px] text-gray-400 mt-0.5">
              Privilege escalation · root-equivalent accounts · service-account shells · admin grants · stale credentials
            </p>
          </div>
          <a
            href="https://attack.mitre.org/tactics/TA0004/"
            target="_blank" rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold bg-blue-50 border border-blue-200 text-blue-700 rounded-xl hover:bg-blue-100 transition-all flex-shrink-0"
          >
            <ExternalLink className="w-3 h-3" />MITRE ATT&amp;CK
          </a>
        </div>

        <div className="flex gap-2">
          <StatTile label="Identity Incidents" value={stats.total} sub="total findings"
            icon={<Database className="w-3.5 h-3.5" />} valueClass="text-gray-800" />
          <StatTile label="Critical / High" value={stats.criticalHigh} sub="severity ≥ high"
            icon={<AlertTriangle className="w-3.5 h-3.5" />}
            valueClass={stats.criticalHigh > 0 ? "text-red-600" : "text-gray-600"}
            warn={stats.criticalHigh > 0} />
          <StatTile label="Root-Equivalent" value={stats.rootEquiv} sub="non-root UID 0"
            icon={<KeyRound className="w-3.5 h-3.5" />}
            valueClass={stats.rootEquiv > 0 ? "text-red-600" : "text-gray-600"}
            warn={stats.rootEquiv > 0} />
          <StatTile label="Service Shells" value={stats.svcShells} sub="UID &lt; 500 interactive"
            icon={<Terminal className="w-3.5 h-3.5" />}
            valueClass={stats.svcShells > 0 ? "text-amber-600" : "text-gray-600"} />
          <StatTile label="Privilege Changes" value={stats.privChange} sub="admin granted / spike"
            icon={<UserPlus className="w-3.5 h-3.5" />}
            valueClass={stats.privChange > 0 ? "text-blue-600" : "text-gray-600"} />
        </div>
      </div>

      {/* ── Filter controls ──────────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 pt-4 pb-3 space-y-3">
        {/* Signal chips */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider whitespace-nowrap">Signal</span>
          <div className="flex items-center gap-1 flex-wrap">
            <button
              onClick={() => setSignalFilter("all")}
              className={cn("flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                signalFilter === "all" ? "bg-blue-600 text-white border-blue-600 shadow-sm"
                  : "bg-white text-gray-500 border-gray-200 hover:border-gray-300 hover:bg-gray-50")}
            >
              All
            </button>
            {IDENTITY_SIGNALS.map(s => {
              const count = signalCounts[s.key] ?? 0;
              if (count === 0) return null;
              return (
                <button
                  key={s.key}
                  onClick={() => setSignalFilter(s.key)}
                  className={cn("flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                    signalFilter === s.key
                      ? s.key === "uid0" ? "bg-red-600 text-white border-red-600 shadow-sm"
                        : "bg-blue-600 text-white border-blue-600 shadow-sm"
                      : "bg-white text-gray-500 border-gray-200 hover:border-gray-300 hover:bg-gray-50")}
                >
                  {s.label}
                  <span className={cn("ml-0.5 text-[8px] font-black px-1 rounded",
                    signalFilter === s.key ? "bg-white/20 text-white" : "bg-gray-100 text-gray-600")}>
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
                !validatedOnly ? "bg-white text-blue-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
            >
              All Identity
            </button>
            <button
              onClick={() => setValidatedOnly(true)}
              className={cn("flex items-center gap-1 px-3 py-1.5 rounded-md text-[10px] font-bold transition-all",
                validatedOnly ? "bg-white text-emerald-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
            >
              <CheckCircle2 className="w-3 h-3" />Validated
            </button>
          </div>

          {validatedOnly && (
            <span className="ml-auto text-[9px] text-emerald-700 font-semibold flex items-center gap-1 bg-emerald-50 px-2 py-1 rounded border border-emerald-200">
              <CheckCircle2 className="w-3 h-3" />precision_score ≥ threshold
            </span>
          )}
        </div>

        {/* Playbook hint */}
        {(hasRootEquiv || stats.svcShells > 0) && (
          <div className="flex items-start gap-2.5 px-3 py-2.5 bg-red-50 border border-red-200 rounded-xl">
            <Shield className="w-3.5 h-3.5 text-red-600 flex-shrink-0 mt-0.5" />
            <div className="text-[10px] text-red-900 leading-relaxed">
              <span className="font-bold">Containment playbook: </span>
              confirm the account against your directory of record with{" "}
              <code className="font-mono text-[9px] bg-red-100 px-1 rounded">dscl . -read /Users/&lt;name&gt;</code>,
              check its login history via{" "}
              <code className="font-mono text-[9px] bg-red-100 px-1 rounded">last &lt;name&gt;</code>,
              then disable rather than delete — preserving the account preserves the forensic trail.
              Set service accounts back to{" "}
              <code className="font-mono text-[9px] bg-red-100 px-1 rounded">/usr/bin/false</code>.
            </div>
          </div>
        )}
      </div>

      {/* ── Main detection table ─────────────────────────────────────────── */}
      <TerrainDetectionPage
        key={pageKey}
        apiUrl={baseUrl}
        accent="blue"
        emptyMsg={
          validatedOnly
            ? "No validated findings in Identity."
            : "No identity findings yet. Findings appear when the users collector reports a risky account or a behavioural account anomaly fires."
        }
        initialSearch={selectedSignal?.search}
        columns={[
          { key: "source",          label: "Signal",     render: f => <SignalChipCell f={f} /> },
          { key: "confidence_pct",  label: "Confidence", render: f => <ConfPct f={f} /> },
          { key: "composite_score", label: "Risk",       render: f => <RiskScore f={f} /> },
          { key: "mitre_technique", label: "MITRE",      render: f => <span className="text-[9px] font-mono text-gray-400 truncate max-w-[80px] block">{f.mitre_technique ?? "—"}</span> },
        ]}
      />
    </div>
  );
}
