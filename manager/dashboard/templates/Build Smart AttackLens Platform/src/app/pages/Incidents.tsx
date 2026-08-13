/**
 * Incidents.tsx — Unified SOC incident queue.
 *
 * Feature parity with enterprise SOC platforms (CrowdStrike, Cortex XDR, Sentinel):
 *   • Terrain filter tabs with live finding counts
 *   • Status filter row: All | New | Triaging | Investigating | In Remediation | Remediated
 *   • View toggle: List (table) | Timeline (day-grouped chronological)
 *   • Validated / All toggle
 *   • Case Management slide-over (transactional backend + legacy import)
 *   • Severity distribution strip across all findings
 */
import React, { useState, useMemo, useCallback, useEffect } from "react";
import { useSearchParams } from "react-router";
import {
  Layers, CheckCircle2, Globe, Network, Shield, User, Activity,
  Clock, LayoutList, GitBranch, Plus, X, ChevronDown, ChevronRight,
  AlertTriangle, Briefcase, Tag, Calendar, Database, Radio,
  Share2, TrendingUp, Zap,
} from "lucide-react";
import { cn } from "../../lib/utils";
import { useTerrainCatalog, type TerrainMeta } from "../lib/terrainCatalog";
import { TerrainDetectionPage, TerrainChip, useDetectionData, type DetectionFinding } from "./DetectionShared";
import {
  createCase as createCaseRecord,
  importLegacyCases as importLegacyCaseRecords,
  listCases as listCaseRecords,
  updateCase as updateCaseRecord,
} from "../lib/caseClient";

// ── Types ─────────────────────────────────────────────────────────────────────

type TerrainTab = string;
type StatusTab  = "all" | "new" | "triaging" | "investigating" | "in_remediation" | "remediated";
type ViewMode   = "list" | "timeline";

export interface IncidentQueryState {
  terrain: TerrainTab;
  status: StatusTab;
  validated: boolean;
  view: ViewMode;
}

export function parseIncidentQuery(params: URLSearchParams): IncidentQueryState {
  const status = params.get("status");
  const view = params.get("view");
  return {
    terrain: params.get("terrain") || "all",
    status: (["all", "new", "triaging", "investigating", "in_remediation", "remediated"].includes(status || "")
      ? status : "all") as StatusTab,
    validated: params.get("validated") === "1",
    view: view === "timeline" ? "timeline" : "list",
  };
}

export function updateIncidentQuery(
  current: URLSearchParams,
  state: IncidentQueryState,
): URLSearchParams {
  const next = new URLSearchParams(current);
  const setOrDelete = (key: string, value: string, defaultValue: string) => {
    if (value === defaultValue) next.delete(key); else next.set(key, value);
  };
  setOrDelete("terrain", state.terrain, "all");
  setOrDelete("status", state.status, "all");
  setOrDelete("view", state.view, "list");
  if (state.validated) next.set("validated", "1"); else next.delete("validated");
  return next;
}

type CasePriority = "critical" | "high" | "medium" | "low";
type CaseStatus   = "open" | "in_progress" | "resolved" | "closed";

export interface ALCase {
  id:          number | string;
  external_id?: string;
  title:       string;
  description: string;
  priority:    CasePriority;
  status:      CaseStatus;
  assignee:    string;
  owner_user_id?: string;
  tags:        string[];
  findings:    number[];
  created_at:  number;
  updated_at:  number;
  version?:     number;
}

// ── Case management helpers ────────────────────────────────────────────────────

function loadLegacyCases(): ALCase[] {
  try { return JSON.parse(localStorage.getItem("al_cases") ?? "[]"); }
  catch { return []; }
}

export function parseCaseList(value: unknown): ALCase[] {
  if (!value || typeof value !== "object") return [];
  const rows = (value as { cases?: unknown }).cases;
  if (!Array.isArray(rows)) return [];
  return rows.filter((row): row is Record<string, unknown> => !!row && typeof row === "object")
    .map((row) => ({
      id: (typeof row.id === "number" || typeof row.id === "string") ? row.id : "",
      external_id: typeof row.external_id === "string" ? row.external_id : "",
      title: typeof row.title === "string" ? row.title : "Untitled case",
      description: typeof row.description === "string" ? row.description : "",
      priority: (["critical", "high", "medium", "low"].includes(String(row.priority))
        ? row.priority : "medium") as CasePriority,
      status: (["open", "in_progress", "resolved", "closed"].includes(String(row.status))
        ? row.status : "open") as CaseStatus,
      assignee: typeof row.owner_user_id === "string" ? row.owner_user_id : "",
      owner_user_id: typeof row.owner_user_id === "string" ? row.owner_user_id : "",
      tags: Array.isArray(row.tags) ? row.tags.filter((tag): tag is string => typeof tag === "string") : [],
      findings: Array.isArray(row.findings) ? row.findings.filter((id): id is number => typeof id === "number") : [],
      created_at: typeof row.created_at === "number" ? row.created_at * 1000 : 0,
      updated_at: typeof row.updated_at === "number" ? row.updated_at * 1000 : 0,
      version: typeof row.version === "number" ? row.version : 1,
    }));
}

export function countOpenCases(value: unknown): number {
  return parseCaseList(value).filter((record) => record.status !== "closed").length;
}

type CaseDraft = Omit<ALCase, "id" | "external_id" | "created_at" | "updated_at" | "version" | "owner_user_id">;

export function buildCaseCreatePayload(draft: CaseDraft) {
  return {
    title: draft.title,
    description: draft.description,
    priority: draft.priority,
    status: draft.status,
    owner_user_id: draft.assignee,
    tags: draft.tags,
    finding_ids: draft.findings,
  };
}

export function buildLegacyCaseImport(values: unknown[]) {
  return {
    cases: values.filter((value): value is Record<string, unknown> => (
      !!value && typeof value === "object"
      && typeof (value as Record<string, unknown>).title === "string"
      && Boolean(String((value as Record<string, unknown>).title).trim())
    )),
  };
}

// ── Terrain tab config ─────────────────────────────────────────────────────────

const TERRAIN_PRESENTATION: Record<string, {
  icon: React.ReactNode; activeCls: string; dotCls: string;
}> = {
  origin:   { icon: <Globe className="w-3 h-3" />, activeCls: "bg-amber-500 text-white border-amber-500", dotCls: "bg-amber-400" },
  vector:   { icon: <Network className="w-3 h-3" />, activeCls: "bg-blue-600 text-white border-blue-600", dotCls: "bg-blue-400" },
  citadels: { icon: <Shield className="w-3 h-3" />, activeCls: "bg-red-600 text-white border-red-600", dotCls: "bg-red-400" },
  identity: { icon: <User className="w-3 h-3" />, activeCls: "bg-indigo-600 text-white border-indigo-600", dotCls: "bg-indigo-400" },
  posture:  { icon: <Activity className="w-3 h-3" />, activeCls: "bg-emerald-600 text-white border-emerald-600", dotCls: "bg-emerald-400" },
  mesh:     { icon: <Share2 className="w-3 h-3" />, activeCls: "bg-cyan-600 text-white border-cyan-600", dotCls: "bg-cyan-400" },
};

export function buildIncidentTerrainTabs(terrains: TerrainMeta[]) {
  return [{
    key: "all", label: "All", icon: <Layers className="w-3 h-3" />,
    activeCls: "bg-orange-500 text-white border-orange-500", dotCls: "bg-orange-400",
  }, ...terrains.map((terrain) => ({
    key: terrain.id,
    label: terrain.label,
    ...(TERRAIN_PRESENTATION[terrain.id] ?? {
      icon: <Layers className="w-3 h-3" />,
      activeCls: "bg-gray-700 text-white border-gray-700",
      dotCls: "bg-gray-400",
    }),
  }))];
}

export function countIncidentsByTerrain(
  findings: Array<{ terrain_id?: string; terrain?: string }>,
): Record<string, number> {
  const counts: Record<string, number> = {};
  findings.forEach((finding) => {
    const terrain = finding.terrain_id || finding.terrain;
    if (terrain) counts[terrain] = (counts[terrain] ?? 0) + 1;
  });
  return counts;
}

const STATUS_TABS: { key: StatusTab; label: string; dotCls: string }[] = [
  { key: "all",            label: "All",            dotCls: "bg-gray-400"   },
  { key: "new",            label: "New",            dotCls: "bg-red-500"    },
  { key: "triaging",       label: "Triaging",       dotCls: "bg-amber-500"  },
  { key: "investigating",  label: "Investigating",   dotCls: "bg-blue-500"   },
  { key: "in_remediation", label: "In Remediation", dotCls: "bg-purple-500" },
  { key: "remediated",     label: "Remediated",     dotCls: "bg-green-500"  },
];

// ── KPI stat tile ─────────────────────────────────────────────────────────────

function StatTile({ label, value, sub, icon, valueClass }: {
  label: string; value: string | number; sub?: string;
  icon: React.ReactNode; valueClass: string;
}) {
  return (
    <div className="flex-1 rounded-xl border border-gray-100 bg-white px-4 py-3">
      <div className="mb-1 opacity-50 text-gray-400">{icon}</div>
      <div className={cn("text-xl font-black tabular-nums leading-none", valueClass)}>{value}</div>
      {sub && <div className="text-[9px] text-gray-400 mt-0.5">{sub}</div>}
      <div className="text-[10px] text-gray-500 font-semibold mt-1">{label}</div>
    </div>
  );
}

// ── Severity distribution bar ─────────────────────────────────────────────────

function SeverityBar({ findings }: { findings: DetectionFinding[] }) {
  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => { if (f.severity in c) c[f.severity as keyof typeof c]++; });
    return c;
  }, [findings]);

  const total = findings.length;
  if (total === 0) return null;

  const SEV = [
    { key: "critical", label: "Critical", cls: "bg-red-500",    text: "text-red-700"    },
    { key: "high",     label: "High",     cls: "bg-amber-500",  text: "text-amber-700"  },
    { key: "medium",   label: "Medium",   cls: "bg-blue-500",   text: "text-blue-700"   },
    { key: "low",      label: "Low",      cls: "bg-green-500",  text: "text-green-700"  },
    { key: "info",     label: "Info",     cls: "bg-gray-300",   text: "text-gray-600"   },
  ] as const;

  return (
    <div className="flex items-center gap-3">
      {/* Stacked bar */}
      <div className="flex-1 flex h-2 rounded-full overflow-hidden bg-gray-100">
        {SEV.map(s => {
          const cnt = counts[s.key];
          if (!cnt) return null;
          return (
            <div
              key={s.key}
              className={cn("h-full transition-all", s.cls)}
              style={{ width: `${Math.round((cnt / total) * 100)}%` }}
              title={`${s.label}: ${cnt}`}
            />
          );
        })}
      </div>
      {/* Legend pills */}
      <div className="flex items-center gap-2 flex-shrink-0">
        {SEV.filter(s => counts[s.key] > 0).map(s => (
          <span key={s.key} className={cn("text-[9px] font-bold tabular-nums", s.text)}>
            {counts[s.key]} {s.label}
          </span>
        ))}
      </div>
    </div>
  );
}

// ── Incident row for category display ─────────────────────────────────────────

function CategoryCell({ f }: { f: DetectionFinding }) {
  return (
    <div className="flex items-center gap-1.5">
      <TerrainChip terrain={f.terrain} />
      {f.category && (
        <span className="text-[9px] text-gray-400 capitalize truncate max-w-[60px]">{f.category}</span>
      )}
    </div>
  );
}

function RiskScore({ f }: { f: DetectionFinding }) {
  const s   = f.composite_score ?? f.score ?? 0;
  const cls = s >= 8 ? "text-red-600 bg-red-50 border-red-200"
              : s >= 6 ? "text-amber-600 bg-amber-50 border-amber-200"
              :          "text-blue-600 bg-blue-50 border-blue-200";
  return (
    <div className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-black tabular-nums", cls)}>
      {s.toFixed(1)}<span className="text-[8px] font-normal opacity-60">/10</span>
    </div>
  );
}

// ── Timeline view ──────────────────────────────────────────────────────────────

const SEV_DOT: Record<string, string> = {
  critical: "bg-red-500 ring-red-200",
  high:     "bg-amber-500 ring-amber-200",
  medium:   "bg-blue-500 ring-blue-200",
  low:      "bg-green-500 ring-green-200",
  info:     "bg-gray-300 ring-gray-100",
};
const SEV_BADGE: Record<string, string> = {
  critical: "bg-red-100 text-red-700",
  high:     "bg-amber-100 text-amber-700",
  medium:   "bg-blue-100 text-blue-700",
  low:      "bg-green-100 text-green-700",
  info:     "bg-gray-100 text-gray-500",
};
const SEV_BORDER: Record<string, string> = {
  critical: "border-l-red-400",
  high:     "border-l-amber-400",
  medium:   "border-l-blue-400",
  low:      "border-l-green-400",
  info:     "border-l-gray-200",
};

function TimelineView({ findings }: { findings: DetectionFinding[] }) {
  const [expandedDays, setExpandedDays] = useState<Record<string, boolean>>({});

  const grouped = useMemo(() => {
    const map: Record<string, DetectionFinding[]> = {};
    [...findings]
      .sort((a, b) => b.last_detected_at - a.last_detected_at)
      .forEach(f => {
        const d   = new Date(f.last_detected_at * 1000);
        const key = d.toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric", year: "numeric" });
        (map[key] ??= []).push(f);
      });
    return Object.entries(map);
  }, [findings]);

  const toggle = (day: string) =>
    setExpandedDays(prev => ({ ...prev, [day]: !(prev[day] ?? true) }));

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-gray-400">
        <Clock className="w-10 h-10 mb-3 opacity-20" />
        <p className="text-sm font-semibold">No incidents to display</p>
        <p className="text-[11px] mt-1">Try adjusting the terrain or status filters</p>
      </div>
    );
  }

  return (
    <div className="px-5 py-5 space-y-6">
      {grouped.map(([day, items]) => {
        const open     = expandedDays[day] ?? true;
        const critCount = items.filter(f => f.severity === "critical" || f.severity === "high").length;
        return (
          <div key={day}>
            {/* Day header */}
            <button
              onClick={() => toggle(day)}
              className="flex items-center gap-2 mb-3 w-full text-left group"
            >
              <div className="flex items-center gap-2">
                {open
                  ? <ChevronDown  className="w-3.5 h-3.5 text-gray-400 group-hover:text-gray-600 transition" />
                  : <ChevronRight className="w-3.5 h-3.5 text-gray-400 group-hover:text-gray-600 transition" />}
                <Calendar className="w-3.5 h-3.5 text-orange-500" />
                <span className="text-[11px] font-bold text-gray-700">{day}</span>
                <span className="text-[10px] text-gray-400">{items.length} incident{items.length !== 1 ? "s" : ""}</span>
                {critCount > 0 && (
                  <span className="text-[9px] font-bold px-1.5 py-0.5 bg-red-100 text-red-700 rounded-full">
                    {critCount} high+
                  </span>
                )}
              </div>
              <div className="flex-1 h-px bg-gray-100 ml-2" />
            </button>

            {open && (
              <div className="ml-5 border-l-2 border-orange-100 pl-4 space-y-2.5">
                {items.map(f => {
                  const sev     = f.severity ?? "info";
                  const dotCls  = SEV_DOT[sev]   ?? SEV_DOT.info;
                  const badgeCls = SEV_BADGE[sev] ?? SEV_BADGE.info;
                  const bdrCls   = SEV_BORDER[sev] ?? SEV_BORDER.info;
                  const ts = new Date(f.last_detected_at * 1000).toLocaleTimeString("en-US", {
                    hour: "2-digit", minute: "2-digit",
                  });
                  const score = f.composite_score ?? f.score ?? 0;
                  return (
                    <div key={f.id} className="relative flex gap-3">
                      {/* Timeline dot */}
                      <div className="flex-shrink-0 flex flex-col items-center">
                        <div className={cn("w-2.5 h-2.5 rounded-full mt-1 ring-2", dotCls)} />
                      </div>

                      {/* Incident card */}
                      <div className={cn(
                        "flex-1 bg-white border border-gray-100 border-l-2 rounded-xl p-3.5 shadow-xs hover:shadow-sm hover:border-orange-200 transition-all cursor-pointer",
                        bdrCls
                      )}>
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex-1 min-w-0">
                            {/* Badge row */}
                            <div className="flex items-center gap-1.5 mb-1.5 flex-wrap">
                              <TerrainChip terrain={f.terrain} />
                              <span className={cn("text-[9px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider", badgeCls)}>
                                {sev}
                              </span>
                              {f.kev && (
                                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-600 text-white uppercase badge-kev-pulse">KEV</span>
                              )}
                              {f.mitre_technique && (
                                <span className="text-[8px] font-mono px-1.5 py-0.5 bg-indigo-50 text-indigo-700 border border-indigo-200 rounded">
                                  {f.mitre_technique}
                                </span>
                              )}
                            </div>

                            {/* Title */}
                            <p className="text-[12px] font-semibold text-gray-800 leading-tight line-clamp-1">{f.title}</p>

                            {/* Description */}
                            {f.description && (
                              <p className="text-[10px] text-gray-500 mt-1 line-clamp-2 leading-relaxed">{f.description}</p>
                            )}

                            {/* Meta row */}
                            <div className="flex items-center gap-3 mt-2 flex-wrap">
                              {f.external_id && (
                                <span className="text-[9px] font-mono text-gray-400">{f.external_id}</span>
                              )}
                              {f.agent_id && (
                                <span className="text-[9px] text-gray-400 bg-gray-50 px-1.5 py-0.5 rounded border border-gray-100 font-mono">
                                  {f.agent_id.slice(0, 12)}…
                                </span>
                              )}
                              {f.status && f.status !== "new" && (
                                <span className="text-[9px] text-gray-400 capitalize">{f.status.replace(/_/g, " ")}</span>
                              )}
                            </div>
                          </div>

                          <div className="flex-shrink-0 flex flex-col items-end gap-1.5">
                            <span className="text-[9px] text-gray-400 font-mono tabular-nums">{ts}</span>
                            <div className={cn(
                              "text-[11px] font-black tabular-nums px-2 py-0.5 rounded-full border",
                              score >= 8 ? "text-red-600 bg-red-50 border-red-200"
                              : score >= 6 ? "text-amber-600 bg-amber-50 border-amber-200"
                              :             "text-blue-600 bg-blue-50 border-blue-200"
                            )}>
                              {score.toFixed(1)}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Case Management Panel ──────────────────────────────────────────────────────

const PRIORITY_COLORS: Record<CasePriority, string> = {
  critical: "bg-red-100 text-red-700 border-red-200",
  high:     "bg-orange-100 text-orange-700 border-orange-200",
  medium:   "bg-amber-100 text-amber-700 border-amber-200",
  low:      "bg-blue-100 text-blue-700 border-blue-200",
};
const STATUS_DOT: Record<CaseStatus, string> = {
  open:        "bg-orange-500",
  in_progress: "bg-blue-500",
  resolved:    "bg-emerald-500",
  closed:      "bg-gray-400",
};
const STATUS_LABEL: Record<CaseStatus, string> = {
  open: "Open", in_progress: "In Progress", resolved: "Resolved", closed: "Closed",
};

function CaseManagementPanel({ onClose }: { onClose: () => void }) {
  const [cases,    setCases]   = useState<ALCase[]>([]);
  const [showNew,  setShowNew] = useState(false);
  const [tagInput, setTagInput] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [legacyCases, setLegacyCases] = useState<ALCase[]>(() => (
    localStorage.getItem("al_cases_migrated") ? [] : loadLegacyCases()
  ));
  const [draft, setDraft] = useState({
    title: "", description: "", priority: "high" as CasePriority,
    status: "open" as CaseStatus, assignee: "", tags: [] as string[], findings: [] as number[],
  });

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const records = await listCaseRecords({ limit: 100 });
      setCases(records.map(row => ({
        ...row,
        assignee: row.owner_user_id,
        created_at: row.created_at * 1000,
        updated_at: row.updated_at * 1000,
      })));
      setError("");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to load cases");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void refresh(); }, [refresh]);

  const submit = async () => {
    if (!draft.title.trim() || saving) return;
    setSaving(true);
    try {
      await createCaseRecord(buildCaseCreatePayload(draft));
      setDraft({ title: "", description: "", priority: "high", status: "open", assignee: "", tags: [], findings: [] });
      setTagInput("");
      setShowNew(false);
      await refresh();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to create case");
    } finally {
      setSaving(false);
    }
  };

  const closeCase = async (caseRecord: ALCase) => {
    if (typeof caseRecord.id !== "number") return;
    try {
      await updateCaseRecord(caseRecord.id, caseRecord.version ?? 1, { status: "closed" });
      await refresh();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to close case");
    }
  };

  const importLegacy = async () => {
    if (!legacyCases.length || saving) return;
    setSaving(true);
    try {
      localStorage.setItem("al_cases_migration_backup", JSON.stringify(legacyCases));
      await importLegacyCaseRecords(buildLegacyCaseImport(legacyCases).cases);
      localStorage.setItem("al_cases_migrated", new Date().toISOString());
      localStorage.removeItem("al_cases");
      setLegacyCases([]);
      await refresh();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to import local cases");
    } finally {
      setSaving(false);
    }
  };

  const openCases = cases.filter(c => c.status !== "closed");

  return (
    <div className="fixed inset-0 z-50 flex">
      {/* Backdrop */}
      <div className="flex-1 bg-black/40 backdrop-blur-[1px]" onClick={onClose} />

      {/* Panel */}
      <div className="w-full sm:w-[min(460px,100vw)] max-w-full bg-white shadow-2xl flex flex-col h-dvh overflow-hidden">

        {/* Header gradient */}
        <div className="h-1 bg-gradient-to-r from-orange-400 via-amber-400 to-orange-500 flex-shrink-0" />

        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100 flex-shrink-0">
          <div className="flex items-center gap-2">
            <Briefcase className="w-4 h-4 text-orange-500" />
            <span className="text-sm font-bold text-gray-800">Case Management</span>
            {openCases.length > 0 && (
              <span className="text-[9px] bg-orange-100 text-orange-700 font-bold px-1.5 py-0.5 rounded-full border border-orange-200">
                {openCases.length} open
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowNew(v => !v)}
              className="flex items-center gap-1 px-2.5 py-1.5 text-[10px] font-bold bg-orange-500 text-white rounded-lg hover:bg-orange-600 transition-all shadow-sm"
            >
              <Plus className="w-3 h-3" />New Case
            </button>
            <button onClick={onClose} className="p-1.5 rounded-lg text-gray-400 hover:text-gray-700 hover:bg-gray-100 transition-all">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {legacyCases.length > 0 && (
          <div className="mx-5 mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 flex items-center justify-between gap-3">
            <div>
              <p className="text-[10px] font-bold text-amber-800">{legacyCases.length} local case{legacyCases.length === 1 ? "" : "s"} found</p>
              <p className="text-[9px] text-amber-700">Import to the backend; a browser backup is kept.</p>
            </div>
            <button onClick={() => void importLegacy()} disabled={saving} className="text-[9px] font-bold rounded-md bg-amber-600 text-white px-2.5 py-1.5 disabled:opacity-50">
              Import
            </button>
          </div>
        )}

        {error && (
          <div className="mx-5 mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-[10px] text-red-700 flex items-center justify-between gap-2">
            <span>{error}</span>
            <button onClick={() => void refresh()} className="font-bold underline">Retry</button>
          </div>
        )}

        {/* New case form */}
        {showNew && (
          <div className="border-b border-gray-100 bg-orange-50/40 px-5 py-4 space-y-3 flex-shrink-0">
            <p className="text-[10px] font-bold text-orange-700 uppercase tracking-wider">Create New Case</p>

            <input
              value={draft.title}
              onChange={e => setDraft(d => ({ ...d, title: e.target.value }))}
              placeholder="Case title *"
              className="w-full px-3 py-2 text-[11px] border border-gray-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-orange-200 focus:border-orange-300"
            />
            <textarea
              value={draft.description}
              onChange={e => setDraft(d => ({ ...d, description: e.target.value }))}
              placeholder="Description (optional)"
              rows={2}
              className="w-full px-3 py-2 text-[11px] border border-gray-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-orange-200 resize-none"
            />

            <div className="flex gap-2">
              <div className="flex-1">
                <label className="block text-[9px] font-bold text-gray-400 uppercase tracking-wider mb-1">Priority</label>
                <select
                  value={draft.priority}
                  onChange={e => setDraft(d => ({ ...d, priority: e.target.value as CasePriority }))}
                  className="w-full px-2 py-1.5 text-[11px] border border-gray-200 rounded-lg bg-white focus:outline-none"
                >
                  {(["critical","high","medium","low"] as CasePriority[]).map(p => (
                    <option key={p} value={p}>{p[0].toUpperCase() + p.slice(1)}</option>
                  ))}
                </select>
              </div>
              <div className="flex-1">
                <label className="block text-[9px] font-bold text-gray-400 uppercase tracking-wider mb-1">Assignee</label>
                <input
                  value={draft.assignee}
                  onChange={e => setDraft(d => ({ ...d, assignee: e.target.value }))}
                  placeholder="analyst@org.com"
                  className="w-full px-2 py-1.5 text-[11px] border border-gray-200 rounded-lg bg-white focus:outline-none"
                />
              </div>
            </div>

            {/* Tag input */}
            <div>
              <label className="block text-[9px] font-bold text-gray-400 uppercase tracking-wider mb-1">Tags</label>
              <input
                value={tagInput}
                onChange={e => setTagInput(e.target.value)}
                onKeyDown={e => {
                  if (e.key === "Enter" && tagInput.trim()) {
                    setDraft(d => ({ ...d, tags: [...d.tags, tagInput.trim()] }));
                    setTagInput("");
                  }
                }}
                placeholder="Add tag + Enter"
                className="w-full px-2 py-1.5 text-[11px] border border-gray-200 rounded-lg bg-white focus:outline-none"
              />
              {draft.tags.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {draft.tags.map(t => (
                    <span key={t} className="inline-flex items-center gap-1 px-2 py-0.5 bg-orange-50 text-orange-700 border border-orange-200 text-[9px] rounded-full">
                      <Tag className="w-2.5 h-2.5" />{t}
                      <button onClick={() => setDraft(d => ({ ...d, tags: d.tags.filter(x => x !== t) }))} className="hover:text-red-500 transition-colors">
                        <X className="w-2.5 h-2.5" />
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div className="flex justify-end gap-2 pt-1">
              <button onClick={() => setShowNew(false)} className="px-3 py-1.5 text-[10px] font-semibold text-gray-500 hover:text-gray-700 transition-colors">
                Cancel
              </button>
              <button
                onClick={() => void submit()}
                disabled={saving}
                className="px-4 py-1.5 text-[10px] font-bold bg-orange-500 text-white rounded-lg hover:bg-orange-600 transition-all shadow-sm disabled:opacity-50"
              >
                {saving ? "Saving…" : "Create Case"}
              </button>
            </div>
          </div>
        )}

        {/* Case list */}
        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center h-40 text-[10px] text-gray-400">Loading cases…</div>
          ) : cases.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-48 text-gray-400">
              <Briefcase className="w-8 h-8 mb-2 opacity-20" />
              <p className="text-[11px] font-semibold">No cases yet</p>
              <p className="text-[10px] mt-0.5">Create a case to start tracking an investigation</p>
            </div>
          ) : (
            <div className="divide-y divide-gray-50">
              {cases.map(c => (
                <div key={c.id} className="px-5 py-4 hover:bg-gray-50/60 transition-all group">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      {/* Status + priority badges */}
                      <div className="flex items-center gap-1.5 mb-1.5 flex-wrap">
                        <span className={cn("text-[9px] font-bold px-1.5 py-0.5 rounded-md border uppercase tracking-wider", PRIORITY_COLORS[c.priority])}>
                          {c.priority}
                        </span>
                        <span className="flex items-center gap-1 text-[9px] text-gray-500">
                          <span className={cn("w-1.5 h-1.5 rounded-full", STATUS_DOT[c.status])} />
                          {STATUS_LABEL[c.status]}
                        </span>
                        {c.tags.map(t => (
                          <span key={t} className="text-[8px] bg-gray-100 text-gray-500 px-1.5 py-0.5 rounded-full border border-gray-200">{t}</span>
                        ))}
                      </div>

                      <p className="text-[12px] font-semibold text-gray-800 leading-tight">{c.title}</p>

                      {c.description && (
                        <p className="text-[10px] text-gray-500 mt-0.5 line-clamp-2 leading-relaxed">{c.description}</p>
                      )}

                      <div className="flex items-center gap-3 mt-2 flex-wrap">
                        <span className="text-[9px] font-mono text-gray-400">{c.external_id || c.id}</span>
                        {c.assignee && (
                          <span className="flex items-center gap-1 text-[9px] text-gray-400">
                            <User className="w-2.5 h-2.5" />{c.assignee}
                          </span>
                        )}
                        {c.findings.length > 0 && (
                          <span className="text-[9px] text-gray-400">{c.findings.length} linked finding{c.findings.length !== 1 ? "s" : ""}</span>
                        )}
                        <span className="text-[9px] text-gray-300">
                          {new Date(c.created_at).toLocaleDateString()}
                        </span>
                      </div>
                    </div>

                    {c.status !== "closed" && (
                      <button
                        onClick={() => void closeCase(c)}
                        className="opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0 px-2 py-1 text-[9px] font-bold text-gray-500 hover:text-red-600 border border-gray-200 hover:border-red-200 rounded-lg"
                      >
                        Close
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Timeline wrapper ───────────────────────────────────────────────────────────

import { useDetectionData as _useDD } from "./DetectionShared";

function TimelineViewWrapper({
  apiUrl, terrainFilter, statusFilter,
}: {
  apiUrl: string; terrainFilter: string; statusFilter: string;
}) {
  const qs = apiUrl.includes("?") ? "&limit=500" : "?limit=500";
  const { findings: raw, loading, error } = _useDD(`${apiUrl}${qs}`);

  const filtered = useMemo(() => {
    let r = raw;
    if (terrainFilter) r = r.filter(f => (f as any).terrain === terrainFilter);
    if (statusFilter)  r = r.filter(f => f.status === statusFilter);
    return r;
  }, [raw, terrainFilter, statusFilter]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24 text-gray-400 gap-2">
        <Clock className="w-5 h-5 animate-pulse text-orange-400" />
        <span className="text-sm font-medium">Loading timeline…</span>
      </div>
    );
  }
  if (error) {
    return (
      <div className="flex items-center justify-center py-20 text-red-400 gap-2">
        <AlertTriangle className="w-5 h-5" />
        <span className="text-sm">{error}</span>
      </div>
    );
  }
  return <TimelineView findings={filtered} />;
}

// ── Main component ─────────────────────────────────────────────────────────────

function IncidentsPage() {
  const [incidentParams, setIncidentParams] = useSearchParams();
  const initialQuery = useMemo(() => parseIncidentQuery(incidentParams), []); // URL at mount
  const terrainCatalog = useTerrainCatalog();
  const terrainTabs = useMemo(
    () => buildIncidentTerrainTabs(terrainCatalog),
    [terrainCatalog],
  );
  const [terrain,       setTerrain]       = useState<TerrainTab>(initialQuery.terrain);
  const [statusTab,     setStatusTab]     = useState<StatusTab>(initialQuery.status);
  const [validatedOnly, setValidatedOnly] = useState(initialQuery.validated);
  const [viewMode,      setViewMode]      = useState<ViewMode>(initialQuery.view);
  const [showCases,     setShowCases]     = useState(false);
  const [openCaseCount, setOpenCaseCount] = useState(0);

  const selectQuery = useCallback((patch: Partial<IncidentQueryState>) => {
    const next = {
      terrain, status: statusTab, validated: validatedOnly, view: viewMode, ...patch,
    };
    setTerrain(next.terrain);
    setStatusTab(next.status);
    setValidatedOnly(next.validated);
    setViewMode(next.view);
    setIncidentParams(updateIncidentQuery(incidentParams, next));
  }, [incidentParams, setIncidentParams, statusTab, terrain, validatedOnly, viewMode]);

  // Browser back/forward and shared links are authoritative.
  useEffect(() => {
    const next = parseIncidentQuery(incidentParams);
    setTerrain(next.terrain);
    setStatusTab(next.status);
    setValidatedOnly(next.validated);
    setViewMode(next.view);
  }, [incidentParams]);

  // Case badges must never block the incident page. The old implementation
  // called an undefined synchronous `loadCases()` during render, which caused
  // a ReferenceError before the queue could open. Load the count defensively;
  // the case drawer performs the authoritative refresh when opened.
  useEffect(() => {
    let cancelled = false;
    void listCaseRecords({ limit: 100 })
      .then((records) => {
        if (!cancelled) setOpenCaseCount(records.filter((record) => record.status !== "closed").length);
      })
      .catch(() => {
        if (!cancelled) setOpenCaseCount(0);
      });
    return () => { cancelled = true; };
  }, []);

  // Fetch all findings for domain stats + terrain counts
  const statsUrl  = validatedOnly
    ? "/api/v1/detection/all?validated_only=true"
    : "/api/v1/detection/all";
  const statsSep = statsUrl.includes("?") ? "&" : "?";
  const { findings: allRaw, error: statsError, refetch: refetchStats } = useDetectionData(`${statsUrl}${statsSep}limit=1000`);

  // Domain-level stats
  const stats = useMemo(() => ({
    total:    allRaw.length,
    critical: allRaw.filter(f => f.severity === "critical").length,
    high:     allRaw.filter(f => f.severity === "high").length,
    kev:      allRaw.filter(f => f.kev).length,
    new:      allRaw.filter(f => f.status === "new").length,
  }), [allRaw]);

  // Per-terrain counts for chip badges
  const terrainCounts = useMemo(() => countIncidentsByTerrain(allRaw), [allRaw]);

  // Table API URL
  const apiUrl = validatedOnly
    ? "/api/v1/detection/all?validated_only=true"
    : "/api/v1/detection/all";

  const terrainFilter = terrain === "all" ? "" : terrain;
  const statusFilter  = statusTab === "all" ? "" : statusTab;
  const pageKey = `${terrain}:${statusTab}:${validatedOnly}`;

  return (
    <div className="space-y-0 pb-6">

      {/* ── Domain header + KPIs ─────────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 py-4">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-9 h-9 rounded-xl bg-orange-50 border border-orange-100 flex items-center justify-center flex-shrink-0">
            <Layers className="w-4.5 h-4.5 text-orange-600" />
          </div>
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-bold text-gray-900">All Incidents — Unified SOC Queue</h2>
            <p className="text-[10px] text-gray-400 mt-0.5">
              Every active finding across all attack terrains · prioritised by composite risk score
            </p>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            {/* View toggle */}
            <div className="inline-flex bg-gray-100 rounded-lg p-0.5">
              <button
                onClick={() => selectQuery({ view: "list" })}
                className={cn("inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[10px] font-bold transition-all",
                  viewMode === "list" ? "bg-white text-orange-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
              >
                <LayoutList className="w-3 h-3" />List
              </button>
              <button
                onClick={() => selectQuery({ view: "timeline" })}
                className={cn("inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[10px] font-bold transition-all",
                  viewMode === "timeline" ? "bg-white text-orange-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
              >
                <GitBranch className="w-3 h-3" />Timeline
              </button>
            </div>

            {/* Manage Cases */}
            <button
              onClick={() => setShowCases(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold bg-white border border-gray-200 text-gray-700 rounded-xl hover:border-orange-300 hover:text-orange-600 hover:bg-orange-50 transition-all"
            >
              <Briefcase className="w-3 h-3" />Cases
              {openCaseCount > 0 && (
                <span className="text-[8px] bg-orange-500 text-white px-1.5 py-0.5 rounded-full font-bold">
                  {openCaseCount}
                </span>
              )}
            </button>
          </div>
        </div>

        {/* KPI strip */}
        <div className="flex gap-2 mb-3">
          <StatTile label="Total Incidents"  value={stats.total}    sub="across all terrains" icon={<Database  className="w-3.5 h-3.5" />} valueClass="text-gray-800" />
          <StatTile label="Critical"         value={stats.critical} sub="severity critical"   icon={<AlertTriangle className="w-3.5 h-3.5" />} valueClass={stats.critical > 0 ? "text-red-600" : "text-gray-500"} />
          <StatTile label="High"             value={stats.high}     sub="severity high"       icon={<Zap      className="w-3.5 h-3.5" />} valueClass={stats.high > 0 ? "text-amber-600" : "text-gray-500"} />
          <StatTile label="KEV Listed"       value={stats.kev}      sub="CISA mandated"       icon={<Radio    className="w-3.5 h-3.5" />} valueClass={stats.kev > 0 ? "text-red-600" : "text-gray-500"} />
          <StatTile label="New / Unreviewed" value={stats.new}      sub="not yet triaged"     icon={<TrendingUp className="w-3.5 h-3.5" />} valueClass={stats.new > 0 ? "text-orange-600" : "text-gray-500"} />
        </div>

        {/* Severity distribution */}
        {allRaw.length > 0 && <SeverityBar findings={allRaw} />}
      </div>

      {statsError && (
        <div className="mx-5 mt-3 flex items-center justify-between gap-3 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-[10px] text-red-700">
          <span className="flex items-center gap-2">
            <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0" />
            Incident summary could not be loaded. Existing results are preserved; retry to refresh.
          </span>
          <button type="button" onClick={refetchStats} className="font-bold underline">Retry</button>
        </div>
      )}

      {/* ── Filter controls ───────────────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 pt-4 pb-3 space-y-3">

        {/* Row 1 — Terrain chips with counts */}
        <div className="flex items-center gap-2 flex-wrap">
          {terrainTabs.map(t => {
            const count = t.key === "all" ? allRaw.length : (terrainCounts[t.key] ?? 0);
            const isActive = terrain === t.key;
            return (
              <button
                key={t.key}
                onClick={() => selectQuery({ terrain: t.key })}
                className={cn(
                  "inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[10px] font-bold border transition-all",
                  isActive ? t.activeCls + " shadow-sm" : "bg-white text-gray-600 border-gray-200 hover:border-gray-300 hover:bg-gray-50"
                )}
              >
                {t.icon}
                {t.label}
                {count > 0 && (
                  <span className={cn(
                    "text-[8px] font-black px-1.5 rounded-full",
                    isActive ? "bg-white/20 text-white" : "bg-gray-100 text-gray-500"
                  )}>
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Row 2 — Status chips + Validated toggle */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1 flex-wrap">
            {STATUS_TABS.map(s => {
              const count = s.key === "all"
                ? allRaw.length
                : allRaw.filter(f => f.status === s.key).length;
              const isActive = statusTab === s.key;
              return (
                <button
                  key={s.key}
                  onClick={() => selectQuery({ status: s.key })}
                  className={cn(
                    "flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                    isActive
                      ? "bg-orange-500 text-white border-orange-500 shadow-sm"
                      : "bg-white text-gray-500 border-gray-200 hover:border-gray-300 hover:bg-gray-50"
                  )}
                >
                  {s.key !== "all" && (
                    <span className={cn("w-1.5 h-1.5 rounded-full", isActive ? "bg-white" : s.dotCls)} />
                  )}
                  {s.label}
                  {count > 0 && count < allRaw.length && (
                    <span className={cn(
                      "text-[8px] font-bold px-1 rounded",
                      isActive ? "bg-orange-400 text-white" : "bg-gray-100 text-gray-500"
                    )}>
                      {count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          <div className="ml-auto inline-flex bg-gray-100 rounded-lg p-0.5">
            <button
              onClick={() => selectQuery({ validated: false })}
              className={cn("px-3 py-1.5 rounded-md text-[10px] font-bold transition-all", !validatedOnly ? "bg-white text-orange-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
            >
              All Incidents
            </button>
            <button
              onClick={() => selectQuery({ validated: true })}
              className={cn("flex items-center gap-1 px-3 py-1.5 rounded-md text-[10px] font-bold transition-all", validatedOnly ? "bg-white text-emerald-600 shadow-sm" : "text-gray-500 hover:text-gray-700")}
            >
              <CheckCircle2 className="w-3 h-3" />Validated
            </button>
          </div>
        </div>
      </div>

      {/* ── Main content ──────────────────────────────────────────────────────── */}
      {viewMode === "list" ? (
        <TerrainDetectionPage
          key={pageKey}
          title={terrain === "all" ? "All Incidents" : `${terrainTabs.find(t => t.key === terrain)?.label ?? terrain} Incidents`}
          subtitle={
            validatedOnly
              ? "Findings that passed the configured validation threshold"
              : terrain !== "all"
              ? `Active findings within the ${terrain} attack terrain`
              : "Every active finding across all attack terrains — unified SOC queue"
          }
          apiUrl={apiUrl}
          accent="red"
          icon={<Layers className="w-5 h-5 text-orange-500" />}
          emptyMsg={
            validatedOnly
              ? "No validated findings. Findings are promoted when precision_score ≥ configured threshold."
              : "No active incidents detected."
          }
          initialTerrainFilter={terrainFilter}
          initialStatusFilter={statusFilter}
          columns={[
            { key: "category",        label: "Terrain", render: (f: DetectionFinding) => <CategoryCell f={f} /> },
            { key: "composite_score", label: "Risk",    render: (f: DetectionFinding) => <RiskScore f={f} /> },
          ]}
        />
      ) : (
        <TimelineViewWrapper
          apiUrl={apiUrl}
          terrainFilter={terrainFilter}
          statusFilter={statusFilter}
        />
      )}

      {/* ── Case panel ────────────────────────────────────────────────────────── */}
      {showCases && <CaseManagementPanel onClose={() => setShowCases(false)} />}
    </div>
  );
}

class IncidentsErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="flex min-h-[320px] flex-col items-center justify-center gap-3 rounded-2xl border border-red-200 bg-red-50 px-6 text-center">
        <AlertTriangle className="h-8 w-8 text-red-500" />
        <div>
          <h2 className="text-sm font-bold text-red-800">All Incidents could not open</h2>
          <p className="mt-1 max-w-md text-[11px] text-red-700">The queue hit an unexpected UI error. Reload the page to retry the current incident view.</p>
        </div>
        <button
          type="button"
          onClick={() => window.location.reload()}
          className="rounded-xl bg-red-600 px-3 py-2 text-[10px] font-bold text-white hover:bg-red-700"
        >
          Reload All Incidents
        </button>
      </div>
    );
  }
}

export default function Incidents() {
  return (
    <IncidentsErrorBoundary>
      <IncidentsPage />
    </IncidentsErrorBoundary>
  );
}
