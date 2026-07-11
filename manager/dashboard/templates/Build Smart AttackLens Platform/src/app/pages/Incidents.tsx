/**
 * Incidents.tsx — All Incidents (SOC unified queue)
 *
 * Feature-parity with enterprise SOC platforms (CrowdStrike, Cortex XDR, Sentinel):
 *   • Terrain filter chips: All | Origin | Vector | Citadels | Identity | Posture
 *   • View toggle: List (table) | Timeline (day-grouped chronological)
 *   • Status filter row: All | New | Triaging | Investigating | In Remediation | Remediated
 *   • Validated/All toggle
 *   • Manage Cases slide-over panel (localStorage-backed ALCase objects)
 */
import React, { useState, useMemo, useCallback } from "react";
import {
  Layers, CheckCircle2, Globe, Network, Shield, User, Activity,
  Clock, LayoutList, GitBranch, Plus, X, ChevronDown, ChevronRight,
  AlertTriangle, Briefcase, Tag, Calendar
} from "lucide-react";
import { cn } from "../../lib/utils";
import { TerrainDetectionPage, TerrainChip, type DetectionFinding } from "./DetectionShared";

// ── Types ─────────────────────────────────────────────────────────────────────

type TerrainTab = "all" | "origin" | "vector" | "citadels" | "identity" | "posture";
type StatusTab  = "all" | "new" | "triaging" | "investigating" | "in_remediation" | "remediated";
type ViewMode   = "list" | "timeline";

type CasePriority = "critical" | "high" | "medium" | "low";
type CaseStatus   = "open" | "in_progress" | "resolved" | "closed";

export interface ALCase {
  id:          string;
  title:       string;
  description: string;
  priority:    CasePriority;
  status:      CaseStatus;
  assignee:    string;
  tags:        string[];
  findings:    number[];
  created_at:  number;
  updated_at:  number;
}

// ── Case management helpers ────────────────────────────────────────────────────

function loadCases(): ALCase[] {
  try {
    return JSON.parse(localStorage.getItem("al_cases") ?? "[]");
  } catch {
    return [];
  }
}

function saveCases(cases: ALCase[]) {
  localStorage.setItem("al_cases", JSON.stringify(cases));
}

function createCase(draft: Omit<ALCase, "id" | "created_at" | "updated_at">): ALCase {
  const now  = Date.now();
  const id   = `CASE-${now.toString(36).toUpperCase()}`;
  const c: ALCase = { ...draft, id, created_at: now, updated_at: now };
  saveCases([...loadCases(), c]);
  return c;
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function CategoryCell({ f }: { f: DetectionFinding }) {
  return (
    <div className="flex items-center gap-1.5">
      <TerrainChip terrain={f.terrain} />
      {f.category && <span className="text-[10px] text-gray-500 capitalize">{f.category}</span>}
    </div>
  );
}

function RiskScore({ f }: { f: DetectionFinding }) {
  const s   = f.composite_score ?? f.score;
  const clr = s >= 8 ? "text-red-600" : s >= 6 ? "text-amber-600" : "text-blue-600";
  const bg  = s >= 8 ? "bg-red-50 border-red-200" : s >= 6 ? "bg-amber-50 border-amber-200" : "bg-blue-50 border-blue-200";
  return (
    <div className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-black tabular-nums", clr, bg)}>
      {s.toFixed(1)}<span className="text-[8px] font-normal opacity-60">/10</span>
    </div>
  );
}

// ── Timeline view ──────────────────────────────────────────────────────────────

function TimelineView({ findings }: { findings: DetectionFinding[] }) {
  const [expandedDays, setExpandedDays] = useState<Record<string, boolean>>({});

  const grouped = useMemo(() => {
    const map: Record<string, DetectionFinding[]> = {};
    [...findings]
      .sort((a, b) => b.last_detected_at - a.last_detected_at)
      .forEach(f => {
        const d = new Date(f.last_detected_at * 1000);
        const key = d.toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric", year: "numeric" });
        (map[key] ??= []).push(f);
      });
    return Object.entries(map);
  }, [findings]);

  const toggle = (day: string) =>
    setExpandedDays(prev => ({ ...prev, [day]: !(prev[day] ?? true) }));

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-gray-400">
        <Clock className="w-10 h-10 mb-3 opacity-30" />
        <p className="text-sm font-medium">No incidents to display</p>
      </div>
    );
  }

  return (
    <div className="px-5 py-4 space-y-6">
      {grouped.map(([day, items]) => {
        const open = expandedDays[day] ?? true;
        return (
          <div key={day}>
            {/* Day header */}
            <button
              onClick={() => toggle(day)}
              className="flex items-center gap-2 mb-3 group w-full text-left"
            >
              <div className="flex items-center gap-2">
                {open
                  ? <ChevronDown className="w-3.5 h-3.5 text-gray-400" />
                  : <ChevronRight className="w-3.5 h-3.5 text-gray-400" />}
                <Calendar className="w-3.5 h-3.5 text-orange-500" />
                <span className="text-[11px] font-bold text-gray-700">{day}</span>
                <span className="text-[10px] text-gray-400 ml-1">{items.length} finding{items.length !== 1 ? "s" : ""}</span>
              </div>
              <div className="flex-1 h-px bg-gray-100 ml-2" />
            </button>

            {open && (
              <div className="ml-5 border-l-2 border-orange-100 pl-4 space-y-3">
                {items.map(f => {
                  const sev = f.severity ?? "info";
                  const sevColor: Record<string, string> = {
                    critical: "bg-red-500", high: "bg-orange-500",
                    medium: "bg-amber-400", low: "bg-blue-400", info: "bg-gray-300",
                  };
                  const ts = new Date(f.last_detected_at * 1000).toLocaleTimeString("en-US", {
                    hour: "2-digit", minute: "2-digit",
                  });
                  return (
                    <div key={f.id} className="relative flex gap-3">
                      {/* Timeline dot */}
                      <div className="flex-shrink-0 flex flex-col items-center">
                        <div className={cn("w-2 h-2 rounded-full mt-1.5 ring-2 ring-white", sevColor[sev] ?? "bg-gray-300")} />
                      </div>

                      {/* Card */}
                      <div className="flex-1 bg-white border border-gray-100 rounded-xl p-3 shadow-xs hover:shadow-sm hover:border-orange-200 transition-all cursor-pointer">
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-1.5 mb-0.5 flex-wrap">
                              <TerrainChip terrain={f.terrain} />
                              <span className={cn(
                                "text-[9px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider",
                                sev === "critical" ? "bg-red-100 text-red-700" :
                                sev === "high"     ? "bg-orange-100 text-orange-700" :
                                sev === "medium"   ? "bg-amber-100 text-amber-700" :
                                                      "bg-gray-100 text-gray-600"
                              )}>{sev}</span>
                              {f.kev && (
                                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-600 text-white uppercase tracking-wider">KEV</span>
                              )}
                            </div>
                            <p className="text-[11px] font-semibold text-gray-800 leading-tight line-clamp-1">{f.title}</p>
                            {f.description && (
                              <p className="text-[10px] text-gray-500 mt-0.5 line-clamp-2">{f.description}</p>
                            )}
                          </div>
                          <div className="flex-shrink-0 flex flex-col items-end gap-1">
                            <span className="text-[9px] text-gray-400 font-mono tabular-nums">{ts}</span>
                            <div className={cn(
                              "text-[10px] font-black tabular-nums px-1.5 py-0.5 rounded-full border",
                              (f.composite_score ?? f.score) >= 8 ? "text-red-600 bg-red-50 border-red-200" :
                              (f.composite_score ?? f.score) >= 6 ? "text-amber-600 bg-amber-50 border-amber-200" :
                                                                      "text-blue-600 bg-blue-50 border-blue-200"
                            )}>{(f.composite_score ?? f.score).toFixed(1)}</div>
                          </div>
                        </div>
                        {(f.external_id || f.agent_id) && (
                          <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                            {f.external_id && (
                              <span className="text-[9px] font-mono text-gray-400">{f.external_id}</span>
                            )}
                            {f.agent_id && (
                              <span className="text-[9px] text-gray-400 bg-gray-50 px-1.5 py-0.5 rounded border border-gray-100">
                                {f.agent_id.slice(0, 12)}…
                              </span>
                            )}
                          </div>
                        )}
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

function CaseManagementPanel({ onClose }: { onClose: () => void }) {
  const [cases, setCases]         = useState<ALCase[]>(loadCases);
  const [showNew, setShowNew]     = useState(false);
  const [draft, setDraft]         = useState({
    title: "", description: "", priority: "high" as CasePriority,
    status: "open" as CaseStatus, assignee: "", tags: [] as string[], findings: [] as number[],
  });
  const [tagInput, setTagInput]   = useState("");

  const refresh = () => setCases(loadCases());

  const submit = () => {
    if (!draft.title.trim()) return;
    createCase(draft);
    setDraft({ title: "", description: "", priority: "high", status: "open", assignee: "", tags: [], findings: [] });
    setTagInput("");
    setShowNew(false);
    refresh();
  };

  const closeCase = (id: string) => {
    const updated = loadCases().map(c =>
      c.id === id ? { ...c, status: "closed" as CaseStatus, updated_at: Date.now() } : c
    );
    saveCases(updated);
    refresh();
  };

  const priorityColors: Record<CasePriority, string> = {
    critical: "bg-red-100 text-red-700 border-red-200",
    high:     "bg-orange-100 text-orange-700 border-orange-200",
    medium:   "bg-amber-100 text-amber-700 border-amber-200",
    low:      "bg-blue-100 text-blue-700 border-blue-200",
  };

  const statusDot: Record<CaseStatus, string> = {
    open:        "bg-orange-500",
    in_progress: "bg-blue-500",
    resolved:    "bg-emerald-500",
    closed:      "bg-gray-400",
  };

  return (
    <div className="fixed inset-0 z-50 flex">
      {/* Backdrop */}
      <div className="flex-1 bg-black/40 backdrop-blur-[1px]" onClick={onClose} />

      {/* Panel */}
      <div className="w-[440px] bg-white shadow-2xl flex flex-col h-full overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100 bg-gradient-to-r from-orange-50 to-white">
          <div className="flex items-center gap-2">
            <Briefcase className="w-4 h-4 text-orange-500" />
            <span className="text-sm font-bold text-gray-800">Case Management</span>
            <span className="text-[9px] bg-orange-100 text-orange-700 font-bold px-1.5 py-0.5 rounded-full">
              {cases.filter(c => c.status !== "closed").length} open
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowNew(v => !v)}
              className="flex items-center gap-1 px-2.5 py-1.5 text-[10px] font-bold bg-orange-500 text-white rounded-lg hover:bg-orange-600 transition-all"
            >
              <Plus className="w-3 h-3" />New Case
            </button>
            <button onClick={onClose} className="p-1.5 rounded-lg text-gray-400 hover:text-gray-700 hover:bg-gray-100 transition-all">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* New case form */}
        {showNew && (
          <div className="border-b border-gray-100 bg-orange-50/40 px-5 py-4 space-y-3">
            <p className="text-[10px] font-bold text-orange-700 uppercase tracking-wider">New Case</p>
            <input
              value={draft.title}
              onChange={e => setDraft(d => ({ ...d, title: e.target.value }))}
              placeholder="Case title *"
              className="w-full px-3 py-2 text-[11px] border border-gray-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-orange-200"
            />
            <textarea
              value={draft.description}
              onChange={e => setDraft(d => ({ ...d, description: e.target.value }))}
              placeholder="Description (optional)"
              rows={2}
              className="w-full px-3 py-2 text-[11px] border border-gray-200 rounded-lg bg-white focus:outline-none focus:ring-2 focus:ring-orange-200 resize-none"
            />
            <div className="flex gap-2">
              <select
                value={draft.priority}
                onChange={e => setDraft(d => ({ ...d, priority: e.target.value as CasePriority }))}
                className="flex-1 px-2 py-1.5 text-[10px] border border-gray-200 rounded-lg bg-white focus:outline-none"
              >
                {(["critical","high","medium","low"] as CasePriority[]).map(p => (
                  <option key={p} value={p}>{p[0].toUpperCase() + p.slice(1)}</option>
                ))}
              </select>
              <input
                value={draft.assignee}
                onChange={e => setDraft(d => ({ ...d, assignee: e.target.value }))}
                placeholder="Assignee"
                className="flex-1 px-2 py-1.5 text-[10px] border border-gray-200 rounded-lg bg-white focus:outline-none"
              />
            </div>
            <div className="flex gap-2">
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
                className="flex-1 px-2 py-1.5 text-[10px] border border-gray-200 rounded-lg bg-white focus:outline-none"
              />
            </div>
            {draft.tags.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {draft.tags.map(t => (
                  <span key={t} className="inline-flex items-center gap-1 px-2 py-0.5 bg-gray-100 text-gray-600 text-[9px] rounded-full">
                    <Tag className="w-2.5 h-2.5" />{t}
                    <button onClick={() => setDraft(d => ({ ...d, tags: d.tags.filter(x => x !== t) }))} className="hover:text-red-500">
                      <X className="w-2.5 h-2.5" />
                    </button>
                  </span>
                ))}
              </div>
            )}
            <div className="flex justify-end gap-2">
              <button onClick={() => setShowNew(false)} className="px-3 py-1.5 text-[10px] text-gray-500 hover:text-gray-700 transition-all">Cancel</button>
              <button onClick={submit} className="px-3 py-1.5 text-[10px] font-bold bg-orange-500 text-white rounded-lg hover:bg-orange-600 transition-all">
                Create Case
              </button>
            </div>
          </div>
        )}

        {/* Case list */}
        <div className="flex-1 overflow-y-auto">
          {cases.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-40 text-gray-400">
              <Briefcase className="w-8 h-8 mb-2 opacity-30" />
              <p className="text-[11px]">No cases yet. Create one to start tracking.</p>
            </div>
          ) : (
            <div className="divide-y divide-gray-50">
              {cases.map(c => (
                <div key={c.id} className="px-5 py-3.5 hover:bg-gray-50/60 transition-all group">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 mb-1 flex-wrap">
                        <span className={cn("text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wider", priorityColors[c.priority])}>
                          {c.priority}
                        </span>
                        <span className="flex items-center gap-1 text-[9px] text-gray-500">
                          <span className={cn("w-1.5 h-1.5 rounded-full", statusDot[c.status])} />
                          {c.status.replace(/_/g, " ")}
                        </span>
                        {c.tags.map(t => (
                          <span key={t} className="text-[9px] bg-gray-100 text-gray-500 px-1.5 py-0.5 rounded-full">{t}</span>
                        ))}
                      </div>
                      <p className="text-[11px] font-semibold text-gray-800 leading-tight">{c.title}</p>
                      {c.description && (
                        <p className="text-[10px] text-gray-500 mt-0.5 line-clamp-2">{c.description}</p>
                      )}
                      <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                        <span className="text-[9px] font-mono text-gray-400">{c.id}</span>
                        {c.assignee && (
                          <span className="flex items-center gap-1 text-[9px] text-gray-400">
                            <User className="w-2.5 h-2.5" />{c.assignee}
                          </span>
                        )}
                        {c.findings.length > 0 && (
                          <span className="text-[9px] text-gray-400">{c.findings.length} finding{c.findings.length !== 1 ? "s" : ""}</span>
                        )}
                        <span className="text-[9px] text-gray-300">
                          {new Date(c.created_at).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                    {c.status !== "closed" && (
                      <button
                        onClick={() => closeCase(c.id)}
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

// ── Terrain tab config ─────────────────────────────────────────────────────────

const TERRAIN_TABS: { key: TerrainTab; label: string; icon: React.ReactNode; color: string }[] = [
  { key: "all",       label: "All",       icon: <Layers className="w-3 h-3" />,   color: "orange" },
  { key: "origin",    label: "Origin",    icon: <Globe className="w-3 h-3" />,    color: "red"    },
  { key: "vector",    label: "Vector",    icon: <Network className="w-3 h-3" />,  color: "purple" },
  { key: "citadels",  label: "Citadels",  icon: <Shield className="w-3 h-3" />,   color: "blue"   },
  { key: "identity",  label: "Identity",  icon: <User className="w-3 h-3" />,     color: "cyan"   },
  { key: "posture",   label: "Posture",   icon: <Activity className="w-3 h-3" />, color: "emerald"},
];

const STATUS_TABS: { key: StatusTab; label: string }[] = [
  { key: "all",            label: "All"            },
  { key: "new",            label: "New"            },
  { key: "triaging",       label: "Triaging"       },
  { key: "investigating",  label: "Investigating"  },
  { key: "in_remediation", label: "In Remediation" },
  { key: "remediated",     label: "Remediated"     },
];

// ── Main component ─────────────────────────────────────────────────────────────

export default function Incidents() {
  const [terrain,       setTerrain]       = useState<TerrainTab>("all");
  const [statusTab,     setStatusTab]     = useState<StatusTab>("all");
  const [validatedOnly, setValidatedOnly] = useState(false);
  const [viewMode,      setViewMode]      = useState<ViewMode>("list");
  const [showCases,     setShowCases]     = useState(false);

  // Build API URL from current terrain selection
  const apiUrl = useMemo(() => {
    const base = validatedOnly
      ? "/api/v1/detection/all?validated_only=true"
      : "/api/v1/detection/all";
    return base;
  }, [validatedOnly]);

  const terrainFilter = terrain === "all" ? "" : terrain;
  const statusFilter  = statusTab === "all" ? "" : statusTab;

  // Key forces TerrainDetectionPage remount when terrain/status/validated changes
  const pageKey = `${terrain}:${statusTab}:${validatedOnly}`;

  return (
    <div className="space-y-0 pb-6">
      {/* ── Top control bar ───────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-100 px-5 pt-4 pb-3 space-y-3">

        {/* Row 1: Terrain filter chips + View toggle + Manage Cases */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1 flex-wrap">
            {TERRAIN_TABS.map(t => (
              <button
                key={t.key}
                onClick={() => setTerrain(t.key)}
                className={cn(
                  "inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[10px] font-bold border transition-all",
                  terrain === t.key
                    ? `bg-${t.color}-500 text-white border-${t.color}-500 shadow-sm`
                    : "bg-white text-gray-600 border-gray-200 hover:border-gray-300 hover:bg-gray-50"
                )}
              >
                {t.icon}{t.label}
              </button>
            ))}
          </div>

          <div className="ml-auto flex items-center gap-2">
            {/* View toggle */}
            <div className="inline-flex bg-gray-100 rounded-lg p-0.5">
              <button
                onClick={() => setViewMode("list")}
                className={cn(
                  "inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[10px] font-bold transition-all",
                  viewMode === "list" ? "bg-white text-orange-600 shadow-sm" : "text-gray-500 hover:text-gray-700"
                )}
              >
                <LayoutList className="w-3 h-3" />List
              </button>
              <button
                onClick={() => setViewMode("timeline")}
                className={cn(
                  "inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[10px] font-bold transition-all",
                  viewMode === "timeline" ? "bg-white text-orange-600 shadow-sm" : "text-gray-500 hover:text-gray-700"
                )}
              >
                <GitBranch className="w-3 h-3" />Timeline
              </button>
            </div>

            {/* Manage Cases */}
            <button
              onClick={() => setShowCases(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-bold bg-white border border-gray-200 text-gray-700 rounded-xl hover:border-orange-300 hover:text-orange-600 hover:bg-orange-50 transition-all"
            >
              <Briefcase className="w-3 h-3" />Manage Cases
              {loadCases().filter(c => c.status !== "closed").length > 0 && (
                <span className="text-[8px] bg-orange-500 text-white px-1.5 py-0.5 rounded-full font-bold">
                  {loadCases().filter(c => c.status !== "closed").length}
                </span>
              )}
            </button>
          </div>
        </div>

        {/* Row 2: Status chips + Validated toggle */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1 flex-wrap">
            {STATUS_TABS.map(s => (
              <button
                key={s.key}
                onClick={() => setStatusTab(s.key)}
                className={cn(
                  "px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all",
                  statusTab === s.key
                    ? "bg-orange-500 text-white border-orange-500"
                    : "bg-white text-gray-500 border-gray-200 hover:border-gray-300 hover:bg-gray-50"
                )}
              >
                {s.label}
              </button>
            ))}
          </div>

          <div className="ml-auto flex items-center gap-2">
            {/* Validated/All toggle */}
            <div className="inline-flex bg-gray-100 rounded-lg p-0.5" role="group">
              <button
                onClick={() => setValidatedOnly(false)}
                className={cn(
                  "px-3 py-1.5 rounded-md text-[10px] font-bold transition-all",
                  !validatedOnly ? "bg-white text-orange-600 shadow-sm" : "text-gray-500 hover:text-gray-700"
                )}
              >
                All Incidents
              </button>
              <button
                onClick={() => setValidatedOnly(true)}
                className={cn(
                  "flex items-center gap-1 px-3 py-1.5 rounded-md text-[10px] font-bold transition-all",
                  validatedOnly ? "bg-white text-emerald-600 shadow-sm" : "text-gray-500 hover:text-gray-700"
                )}
              >
                <CheckCircle2 className="w-3 h-3" />Validated
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ── Main content: list or timeline ────────────────────────────── */}
      {viewMode === "list" ? (
        <TerrainDetectionPage
          key={pageKey}
          title={terrain === "all" ? "All Incidents" : `${TERRAIN_TABS.find(t => t.key === terrain)?.label} Incidents`}
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
        /* Timeline view — fetches the same endpoint, filters client-side */
        <TimelineViewWrapper
          apiUrl={apiUrl}
          terrainFilter={terrainFilter}
          statusFilter={statusFilter}
        />
      )}

      {/* ── Case management panel ──────────────────────────────────────── */}
      {showCases && <CaseManagementPanel onClose={() => setShowCases(false)} />}
    </div>
  );
}

// ── Timeline wrapper — fetches findings and feeds them to TimelineView ─────────

import { useDetectionData } from "./DetectionShared";

function TimelineViewWrapper({
  apiUrl,
  terrainFilter,
  statusFilter,
}: {
  apiUrl:         string;
  terrainFilter:  string;
  statusFilter:   string;
}) {
  const qs = apiUrl.includes("?") ? "&limit=500" : "?limit=500";
  const { findings: raw, loading, error } = useDetectionData(`${apiUrl}${qs}`);

  const filtered = useMemo(() => {
    let r = raw;
    if (terrainFilter) r = r.filter(f => (f as any).terrain === terrainFilter);
    if (statusFilter)  r = r.filter(f => f.status === statusFilter);
    return r;
  }, [raw, terrainFilter, statusFilter]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20 text-gray-400">
        <Clock className="w-5 h-5 animate-pulse mr-2" />
        <span className="text-sm">Loading timeline…</span>
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
