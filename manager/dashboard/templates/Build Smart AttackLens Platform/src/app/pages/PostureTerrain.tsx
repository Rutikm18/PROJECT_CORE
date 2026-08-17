/**
 * PostureTerrain — Posture terrain (security controls & device baseline).
 *
 * Surfaces every finding the backend classifies as terrain_id="posture":
 * the engine's `security` analyzer (SIP / Gatekeeper / FileVault / firewall /
 * Lockdown Mode), CIS-style `compliance` failures, `hardware` integrity,
 * `agent_health`, and `battery`.
 *
 * Structurally mirrors ExecutionThreats (Citadels): this terrain spans several
 * real categories, so the page sub-divides by CATEGORY and pushes the choice
 * down to the shared table via initialCategoryFilter (a server-side filter),
 * rather than the title-search fallback Mesh and Identity need.
 *
 * The control breakdown is deliberately aligned with POSTURE_CRITERIA in
 * manager/manager/attacklens/terrain_validators.py — SIP is the anchor
 * criterion there, so it gets the alert strip here.
 */
import { useState, useMemo, type ReactNode } from "react";
import {
  ShieldAlert, CheckCircle2, AlertTriangle, Shield, Database,
  ExternalLink, Lock, ClipboardList, Cpu, HeartPulse,
} from "lucide-react";
import {
  TerrainDetectionPage, useDetectionData, type DetectionFinding,
} from "./DetectionShared";
import { cn } from "../../lib/utils";

// ── Category model ──────────────────────────────────────────────────────────
export interface PostureCategory {
  key: string; label: string; categories: string[];
}

export const POSTURE_CATEGORIES: PostureCategory[] = [
  { key: "security",     label: "Controls",     categories: ["security", "posture", "sip", "firewall"] },
  { key: "compliance",   label: "Compliance",   categories: ["compliance"] },
  { key: "hardware",     label: "Hardware",     categories: ["hardware"] },
  { key: "agent_health", label: "Agent Health", categories: ["agent_health"] },
  { key: "battery",      label: "Battery",      categories: ["battery"] },
];

/**
 * Canonical security controls, mirroring _CONTROL_ALIASES in
 * manager/manager/attacklens/terrain_validators.py.
 *
 * Two emitters produce these findings and neither agrees with the other:
 *   detections/sbom_posture (routed, the one that actually runs)
 *     evidence {"control_key": "sip_enabled", "status": "disabled"};
 *     item_key is rewritten to "<rule_id>:<hash>" on persist, so it is useless
 *     as a discriminator here.
 *   engine._security (inline fallback)
 *     item_key "sec:sip", evidence {"sip": "disabled"}.
 */
export const POSTURE_CONTROL_KEYS = [
  "sip", "gatekeeper", "filevault", "firewall",
  "secure_boot", "defender_realtime", "bitlocker", "selinux", "apparmor",
] as const;

const CONTROL_ALIASES: Record<string, string> = {
  sip: "sip", sip_enabled: "sip", csrutil: "sip",
  gatekeeper: "gatekeeper", gatekeeper_enabled: "gatekeeper",
  filevault: "filevault", filevault_enabled: "filevault",
  firewall: "firewall", firewall_enabled: "firewall",
  ufw_enabled: "firewall", firewalld_enabled: "firewall", windows_firewall: "firewall",
  secure_boot: "secure_boot",
  defender_realtime: "defender_realtime",
  bitlocker_enabled: "bitlocker", bitlocker: "bitlocker",
  selinux_enforcing: "selinux", selinux: "selinux",
  apparmor_enforcing: "apparmor", apparmor: "apparmor",
};

const OFF_VALUES = new Set([
  "disabled", "off", "false", "no", "inactive", "0", "permissive",
]);

function isOff(value: unknown): boolean {
  if (value === false) return true;
  if (value === true || value == null) return false;
  return OFF_VALUES.has(String(value).trim().toLowerCase());
}

function asEvidence(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object") return value as Record<string, unknown>;
  if (typeof value === "string" && value.trim()) {
    try {
      const parsed = JSON.parse(value);
      if (parsed && typeof parsed === "object") return parsed as Record<string, unknown>;
    } catch { /* evidence is not always JSON — treat as absent */ }
  }
  return {};
}

/**
 * The canonical control a finding reports as disabled, or "" when it reports
 * none. Understands both emitter shapes so a routed-module deployment and an
 * inline one produce the same KPI.
 */
export function disabledControl(
  finding: { item_key?: string; evidence?: unknown },
): string {
  const ev = asEvidence(finding.evidence);

  const controlKey = ev.control_key;
  if (controlKey && isOff(ev.status ?? "disabled")) {
    return CONTROL_ALIASES[String(controlKey).toLowerCase()] ?? String(controlKey).toLowerCase();
  }

  const itemKey = (finding.item_key ?? "").toLowerCase();
  if (itemKey.includes(":")) {
    const tail = itemKey.slice(itemKey.lastIndexOf(":") + 1);
    const canonical = CONTROL_ALIASES[tail];
    if (canonical && isOff(ev[tail] ?? ev[canonical] ?? "disabled")) return canonical;
  }

  for (const [name, value] of Object.entries(ev)) {
    const canonical = CONTROL_ALIASES[name.toLowerCase()];
    if (canonical && isOff(value)) return canonical;
  }
  return "";
}

/** Count findings per category bucket. Exported so the mapping stays tested. */
export function countPostureCategories(
  findings: { category?: string }[],
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const c of POSTURE_CATEGORIES) counts[c.key] = 0;
  for (const f of findings) {
    const cat = (f.category ?? "").toLowerCase();
    for (const c of POSTURE_CATEGORIES) {
      if (c.categories.includes(cat)) { counts[c.key] += 1; break; }
    }
  }
  return counts;
}

/**
 * How many distinct security controls are reported disabled across the fleet.
 * `lockdown_mode` is informational, never a failure, so it is excluded by
 * simply not being in CONTROL_ALIASES.
 */
export function countDisabledControls(
  findings: { item_key?: string; evidence?: unknown }[],
): number {
  const seen = new Set<string>();
  for (const f of findings) {
    const control = disabledControl(f);
    if (control) seen.add(control);
  }
  return seen.size;
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

function CategoryChipCell({ f }: { f: DetectionFinding }) {
  const COLORS: Record<string, string> = {
    security:     "bg-indigo-50 text-indigo-700 border-indigo-200",
    posture:      "bg-indigo-50 text-indigo-700 border-indigo-200",
    compliance:   "bg-sky-50 text-sky-700 border-sky-200",
    hardware:     "bg-teal-50 text-teal-700 border-teal-200",
    agent_health: "bg-amber-50 text-amber-700 border-amber-200",
    battery:      "bg-gray-50 text-gray-700 border-gray-300",
  };
  const cat = (f.category ?? "").toLowerCase();
  const cls = COLORS[cat] ?? "bg-indigo-50 text-indigo-700 border-indigo-200";
  return (
    <span className={cn("text-[9px] font-semibold px-2 py-0.5 rounded-full border", cls)}>
      {f.category}
    </span>
  );
}

// ── KPI stat tile (identical pattern to the other terrain pages) ────────────
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

type CatFilter = "all" | string;

// ── Main ────────────────────────────────────────────────────────────────────
export default function PostureTerrain() {
  const [validatedOnly, setValidatedOnly] = useState(false);
  const [catFilter,     setCatFilter]     = useState<CatFilter>("all");

  const baseUrl = validatedOnly
    ? "/api/v1/detection/all?terrain_id=posture&validated_only=true"
    : "/api/v1/detection/all?terrain_id=posture";
  const statsUrl = `${baseUrl}&limit=500`;

  const { findings: raw } = useDetectionData(statsUrl);

  const catCounts = useMemo(() => countPostureCategories(raw), [raw]);

  const stats = useMemo(() => ({
    total:            raw.length,
    criticalHigh:     raw.filter(f => f.severity === "critical" || f.severity === "high").length,
    controlsDisabled: countDisabledControls(raw),
    compliance:       catCounts["compliance"] ?? 0,
    hardware:         catCounts["hardware"] ?? 0,
  }), [raw, catCounts]);

  // SIP off is the anchor criterion in POSTURE_CRITERIA — a definitive
  // baseline failure that alone floors the validation score at 0.80.
  const sipOff = useMemo(() => raw.some(f => disabledControl(f) === "sip"), [raw]);

  const selectedCat = POSTURE_CATEGORIES.find(c => c.key === catFilter);
  const pageKey = `${validatedOnly}:${catFilter}`;

  return (
    <div className="space-y-0 pb-6">

      {/* ── Alert strip — SIP off is the anchor criterion ─────────────────── */}
      {sipOff && (
        <div className="flex items-center gap-3 px-5 py-2.5 bg-red-700">
          <AlertTriangle className="w-4 h-4 text-white flex-shrink-0 al-heartbeat" />
          <span className="text-[11px] text-white font-bold">
            System Integrity Protection is disabled — the kernel-level baseline is off and
            protected files can be modified. Restore before triaging anything else on this host.
          </span>
          <a
            href="https://attack.mitre.org/techniques/T1562/001/"
            target="_blank" rel="noopener noreferrer"
            className="ml-auto flex items-center gap-1 text-[10px] text-red-200 hover:text-white font-semibold transition-colors flex-shrink-0"
          >
            MITRE T1562.001 <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      )}

      {/* ── Domain header + KPIs ─────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 py-4">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-9 h-9 rounded-xl bg-indigo-50 border border-indigo-100 flex items-center justify-center flex-shrink-0">
            <ShieldAlert className="w-4.5 h-4.5" style={{ color: "#6366F1" }} />
          </div>
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-bold text-gray-900">Posture — Security Controls</h2>
            <p className="text-[10px] text-gray-400 mt-0.5">
              SIP · Gatekeeper · FileVault · firewall · CIS compliance · hardware integrity · agent health
            </p>
          </div>
          <a
            href="https://attack.mitre.org/tactics/TA0005/"
            target="_blank" rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold bg-indigo-50 border border-indigo-200 text-indigo-700 rounded-xl hover:bg-indigo-100 transition-all flex-shrink-0"
          >
            <ExternalLink className="w-3 h-3" />MITRE ATT&amp;CK
          </a>
        </div>

        <div className="flex gap-2">
          <StatTile label="Posture Incidents" value={stats.total} sub="total findings"
            icon={<Database className="w-3.5 h-3.5" />} valueClass="text-gray-800" />
          <StatTile label="Critical / High" value={stats.criticalHigh} sub="severity ≥ high"
            icon={<AlertTriangle className="w-3.5 h-3.5" />}
            valueClass={stats.criticalHigh > 0 ? "text-red-600" : "text-gray-600"}
            warn={stats.criticalHigh > 0} />
          <StatTile label="Controls Disabled" value={stats.controlsDisabled} sub="distinct controls off"
            icon={<Lock className="w-3.5 h-3.5" />}
            valueClass={stats.controlsDisabled > 0 ? "text-red-600" : "text-emerald-600"}
            warn={stats.controlsDisabled >= 2} />
          <StatTile label="Compliance Failures" value={stats.compliance} sub="failed benchmark checks"
            icon={<ClipboardList className="w-3.5 h-3.5" />}
            valueClass={stats.compliance > 0 ? "text-sky-600" : "text-gray-600"} />
          <StatTile label="Hardware Integrity" value={stats.hardware} sub="firmware / device checks"
            icon={<Cpu className="w-3.5 h-3.5" />}
            valueClass={stats.hardware > 0 ? "text-teal-600" : "text-gray-600"} />
        </div>
      </div>

      {/* ── Multi-control banner — the multi_controls_off criterion ───────── */}
      {stats.controlsDisabled >= 2 && (
        <div className="flex items-center gap-3 px-5 py-2 bg-amber-50 border-b border-amber-200">
          <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0" />
          <span className="text-[11px] text-amber-900 font-semibold">
            {stats.controlsDisabled} security controls are off at the same time — coordinated tampering
            or severe misconfiguration. This raises the validation score on every posture finding for the host.
          </span>
        </div>
      )}

      {/* ── Filter controls ──────────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 pt-4 pb-3 space-y-3">
        {/* Category chips */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider whitespace-nowrap">Category</span>
          <div className="flex items-center gap-1 flex-wrap">
            <button
              onClick={() => setCatFilter("all")}
              className={cn("flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                catFilter === "all" ? "bg-indigo-600 text-white border-indigo-600 shadow-sm"
                  : "bg-white text-gray-500 border-gray-200 hover:border-gray-300 hover:bg-gray-50")}
            >
              All
            </button>
            {POSTURE_CATEGORIES.map(c => {
              const count = catCounts[c.key] ?? 0;
              if (count === 0) return null;
              return (
                <button
                  key={c.key}
                  onClick={() => setCatFilter(c.key)}
                  className={cn("flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                    catFilter === c.key ? "bg-indigo-600 text-white border-indigo-600 shadow-sm"
                      : "bg-white text-gray-500 border-gray-200 hover:border-gray-300 hover:bg-gray-50")}
                >
                  {c.label}
                  <span className={cn("ml-0.5 text-[8px] font-black px-1 rounded",
                    catFilter === c.key ? "bg-white/20 text-white" : "bg-gray-100 text-gray-600")}>
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
                !validatedOnly ? "bg-white text-indigo-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
            >
              All Posture
            </button>
            <button
              onClick={() => setValidatedOnly(true)}
              className={cn("flex items-center gap-1 px-3 py-1.5 rounded-md text-[10px] font-bold transition-all",
                validatedOnly ? "bg-white text-emerald-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
            >
              <CheckCircle2 className="w-3 h-3" />Validated
            </button>
          </div>

          {(catCounts["agent_health"] ?? 0) > 0 && (
            <span className="flex items-center gap-1 text-[9px] text-amber-700 font-semibold bg-amber-50 px-2 py-1 rounded border border-amber-200">
              <HeartPulse className="w-3 h-3" />
              {catCounts["agent_health"]} agent-health {catCounts["agent_health"] === 1 ? "gap" : "gaps"} — telemetry may be incomplete
            </span>
          )}

          {validatedOnly && (
            <span className="ml-auto text-[9px] text-emerald-700 font-semibold flex items-center gap-1 bg-emerald-50 px-2 py-1 rounded border border-emerald-200">
              <CheckCircle2 className="w-3 h-3" />precision_score ≥ threshold
            </span>
          )}
        </div>

        {/* Playbook hint */}
        {stats.controlsDisabled > 0 && (
          <div className="flex items-start gap-2.5 px-3 py-2.5 bg-red-50 border border-red-200 rounded-xl">
            <Shield className="w-3.5 h-3.5 text-red-600 flex-shrink-0 mt-0.5" />
            <div className="text-[10px] text-red-900 leading-relaxed">
              <span className="font-bold">Restore playbook: </span>
              verify current state with{" "}
              <code className="font-mono text-[9px] bg-red-100 px-1 rounded">csrutil status</code>,{" "}
              <code className="font-mono text-[9px] bg-red-100 px-1 rounded">spctl --status</code>, and{" "}
              <code className="font-mono text-[9px] bg-red-100 px-1 rounded">fdesetup status</code>.
              SIP can only be re-enabled from Recovery, so treat a SIP-off host as untrusted until
              it is reimaged or restored — an attacker who disabled it already had root.
            </div>
          </div>
        )}
      </div>

      {/* ── Main detection table ─────────────────────────────────────────── */}
      <TerrainDetectionPage
        key={pageKey}
        apiUrl={baseUrl}
        accent="indigo"
        emptyMsg={
          validatedOnly
            ? "No validated findings in Posture."
            : "No posture findings yet. Findings appear when the security collector reports a disabled control, a failed compliance check, or a hardware-integrity gap."
        }
        // The server-side category filter takes a single value. Every bucket
        // has exactly one category the engine actually emits — it is first in
        // the list; the rest are catalogue aliases reserved in terrain_catalog
        // that no emitter uses today. Filtering on [0] is therefore exact.
        initialCategoryFilter={selectedCat?.categories[0]}
        columns={[
          { key: "category",        label: "Category",   render: f => <CategoryChipCell f={f} /> },
          { key: "confidence_pct",  label: "Confidence", render: f => <ConfPct f={f} /> },
          { key: "composite_score", label: "Risk",       render: f => <RiskScore f={f} /> },
          { key: "mitre_technique", label: "MITRE",      render: f => <span className="text-[9px] font-mono text-gray-400 truncate max-w-[80px] block">{f.mitre_technique ?? "—"}</span> },
        ]}
      />
    </div>
  );
}
