/**
 * CustomCorrelationRules.tsx — Analyst-defined correlation rules dashboard.
 *
 * Lets security engineers author rules that:
 *   - Alert on new attack patterns specific to the environment
 *   - Suppress known false positives
 *   - Elevate severity of under-weighted findings
 *   - Tag findings for workflow routing
 */
import { useState, useEffect, useCallback } from "react";
import {
  Plus, Trash2, ToggleLeft, ToggleRight, Edit2, Play,
  CheckCircle2, XCircle, AlertTriangle, Shield, Zap,
  Tag, ChevronDown, ChevronUp, Info, RefreshCw, Filter,
} from "lucide-react";
import { cn } from "../../lib/utils";

// ── Types ─────────────────────────────────────────────────────────────────────

interface ConditionRule {
  field: string;
  op: string;
  value: string | number | string[];
}

interface Conditions {
  operator: "AND" | "OR";
  rules: ConditionRule[];
}

interface CustomRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  action: "alert" | "suppress" | "elevate" | "tag";
  severity: string;
  confidence: number;
  conditions: Conditions;
  required_count: number;
  time_window_hours: number;
  tags: string[];
  attack_chain: { tactic: string; technique: string; label: string }[];
  recommendation: string;
  hit_count: number;
  last_hit_at: number | null;
  created_at: number;
  updated_at: number;
}

interface TestResult {
  would_fire: boolean;
  matched_count: number;
  required_count: number;
  scanned: number;
  matched_findings: { id: number; title: string; category: string; severity: string }[];
}

// ── Constants ─────────────────────────────────────────────────────────────────

const FIELD_OPTIONS = [
  { value: "category",    label: "Category" },
  { value: "severity",    label: "Severity" },
  { value: "source",      label: "Source / Rule ID" },
  { value: "title",       label: "Title" },
  { value: "tag",         label: "Tag" },
  { value: "score",       label: "Score (0-10)" },
  { value: "cvss_score",  label: "CVSS Score" },
  { value: "epss_score",  label: "EPSS Score" },
  { value: "agent_id",    label: "Agent ID" },
  { value: "status",      label: "Status" },
  { value: "assignee",    label: "Assignee" },
];

const OP_OPTIONS: Record<string, { value: string; label: string }[]> = {
  default: [
    { value: "eq",           label: "equals" },
    { value: "neq",          label: "not equals" },
    { value: "contains",     label: "contains" },
    { value: "not_contains", label: "does not contain" },
    { value: "regex",        label: "matches regex" },
    { value: "in",           label: "is one of" },
  ],
  numeric: [
    { value: "gt",  label: "greater than" },
    { value: "gte", label: "≥" },
    { value: "lt",  label: "less than" },
    { value: "lte", label: "≤" },
    { value: "eq",  label: "equals" },
  ],
};

const NUMERIC_FIELDS = new Set(["score", "cvss_score", "epss_score", "required_count"]);

const ACTION_CONFIG = {
  alert:    { icon: <AlertTriangle className="w-3 h-3" />, label: "Alert",    cls: "text-orange-600 bg-orange-50 border-orange-200" },
  suppress: { icon: <XCircle className="w-3 h-3" />,       label: "Suppress", cls: "text-gray-500 bg-gray-50 border-gray-200" },
  elevate:  { icon: <Zap className="w-3 h-3" />,           label: "Elevate",  cls: "text-red-600 bg-red-50 border-red-200" },
  tag:      { icon: <Tag className="w-3 h-3" />,            label: "Tag",      cls: "text-blue-600 bg-blue-50 border-blue-200" },
};

const SEV_DOT: Record<string, string> = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-400",
  info:     "bg-gray-400",
};

const BLANK_RULE: Omit<CustomRule, "id" | "hit_count" | "last_hit_at" | "created_at" | "updated_at"> = {
  name: "",
  description: "",
  enabled: true,
  action: "alert",
  severity: "medium",
  confidence: 70,
  conditions: { operator: "AND", rules: [] },
  required_count: 1,
  time_window_hours: 24,
  tags: [],
  attack_chain: [],
  recommendation: "",
};

// ── API helpers ───────────────────────────────────────────────────────────────

async function apiGet(path: string) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
async function apiPost(path: string, body?: unknown) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
async function apiPut(path: string, body: unknown) {
  const r = await fetch(path, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
async function apiDelete(path: string) {
  const r = await fetch(path, { method: "DELETE" });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SevDot({ sev }: { sev: string }) {
  return <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0 inline-block", SEV_DOT[sev] ?? "bg-gray-400")} />;
}

function ConditionBuilder({
  conditions,
  onChange,
}: {
  conditions: Conditions;
  onChange: (c: Conditions) => void;
}) {
  const addRule = () =>
    onChange({
      ...conditions,
      rules: [...conditions.rules, { field: "category", op: "eq", value: "" }],
    });

  const updateRule = (idx: number, patch: Partial<ConditionRule>) =>
    onChange({
      ...conditions,
      rules: conditions.rules.map((r, i) => (i === idx ? { ...r, ...patch } : r)),
    });

  const removeRule = (idx: number) =>
    onChange({ ...conditions, rules: conditions.rules.filter((_, i) => i !== idx) });

  return (
    <div className="space-y-2">
      {/* AND/OR toggle */}
      <div className="flex items-center gap-2 mb-2">
        <span className="text-[9px] font-semibold text-gray-500 uppercase tracking-wider">Match</span>
        {(["AND", "OR"] as const).map(op => (
          <button
            key={op}
            onClick={() => onChange({ ...conditions, operator: op })}
            className={cn(
              "px-2 py-0.5 rounded text-[9px] font-bold border transition-all",
              conditions.operator === op
                ? "bg-orange-500 text-white border-orange-500"
                : "bg-white text-gray-500 border-gray-200 hover:border-gray-400"
            )}
          >
            {op}
          </button>
        ))}
        <span className="text-[9px] text-gray-400">of the following conditions</span>
      </div>

      {conditions.rules.map((rule, idx) => {
        const isNum = NUMERIC_FIELDS.has(rule.field);
        const ops   = isNum ? OP_OPTIONS.numeric : OP_OPTIONS.default;
        return (
          <div key={idx} className="flex items-center gap-1.5 p-2 bg-gray-50 rounded-lg border border-gray-100">
            <select
              value={rule.field}
              onChange={e => updateRule(idx, { field: e.target.value, op: "eq", value: "" })}
              className="text-[10px] border border-gray-200 rounded px-1.5 py-1 bg-white text-gray-700 flex-shrink-0"
            >
              {FIELD_OPTIONS.map(f => (
                <option key={f.value} value={f.value}>{f.label}</option>
              ))}
            </select>
            <select
              value={rule.op}
              onChange={e => updateRule(idx, { op: e.target.value })}
              className="text-[10px] border border-gray-200 rounded px-1.5 py-1 bg-white text-gray-700 flex-shrink-0"
            >
              {ops.map(o => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
            </select>
            <input
              value={Array.isArray(rule.value) ? rule.value.join(", ") : String(rule.value)}
              onChange={e => {
                const raw = e.target.value;
                const val = rule.op === "in"
                  ? raw.split(",").map(s => s.trim()).filter(Boolean)
                  : isNum ? parseFloat(raw) || 0 : raw;
                updateRule(idx, { value: val });
              }}
              placeholder={rule.op === "in" ? "val1, val2, val3" : "value"}
              className="flex-1 min-w-0 text-[10px] border border-gray-200 rounded px-2 py-1 bg-white text-gray-700"
            />
            <button onClick={() => removeRule(idx)} className="p-1 rounded hover:bg-red-50 text-gray-300 hover:text-red-500 transition-colors">
              <XCircle className="w-3 h-3" />
            </button>
          </div>
        );
      })}

      <button
        onClick={addRule}
        className="flex items-center gap-1.5 text-[9px] text-orange-500 hover:text-orange-700 font-bold py-1 transition-colors"
      >
        <Plus className="w-3 h-3" /> Add condition
      </button>
    </div>
  );
}

// ── Rule Form Modal ───────────────────────────────────────────────────────────

function RuleForm({
  initial,
  onSave,
  onCancel,
  saving,
}: {
  initial: Partial<CustomRule>;
  onSave: (data: typeof BLANK_RULE) => Promise<void>;
  onCancel: () => void;
  saving: boolean;
}) {
  const [form, setForm] = useState<typeof BLANK_RULE>({ ...BLANK_RULE, ...initial });
  const [tagInput, setTagInput] = useState((initial.tags || []).join(", "));

  const set = (patch: Partial<typeof BLANK_RULE>) => setForm(f => ({ ...f, ...patch }));

  const handleSubmit = async () => {
    if (!form.name.trim()) return;
    const tags = tagInput.split(",").map(s => s.trim()).filter(Boolean);
    await onSave({ ...form, tags });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 backdrop-blur-sm p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-white border-b border-gray-100 px-6 py-4 flex items-center justify-between">
          <h2 className="text-sm font-bold text-gray-900">
            {initial.id ? "Edit Correlation Rule" : "New Correlation Rule"}
          </h2>
          <button onClick={onCancel} className="p-1.5 rounded-lg hover:bg-gray-100 text-gray-400">
            <XCircle className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          {/* Name & Description */}
          <div>
            <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider block mb-1">Rule Name *</label>
            <input
              value={form.name}
              onChange={e => set({ name: e.target.value })}
              placeholder="e.g. Dev machine tunnelling suppression"
              className="w-full text-xs border border-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-1 focus:ring-orange-300"
            />
          </div>
          <div>
            <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider block mb-1">Description</label>
            <textarea
              value={form.description}
              onChange={e => set({ description: e.target.value })}
              rows={2}
              placeholder="Why this rule exists and what it detects..."
              className="w-full text-xs border border-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-1 focus:ring-orange-300 resize-none"
            />
          </div>

          {/* Action + Severity + Confidence */}
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider block mb-1">Action</label>
              <select
                value={form.action}
                onChange={e => set({ action: e.target.value as typeof form.action })}
                className="w-full text-xs border border-gray-200 rounded-lg px-2 py-2 bg-white"
              >
                <option value="alert">Alert (create incident)</option>
                <option value="suppress">Suppress (mark FP)</option>
                <option value="elevate">Elevate severity</option>
                <option value="tag">Tag findings</option>
              </select>
            </div>
            <div>
              <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider block mb-1">Severity</label>
              <select
                value={form.severity}
                onChange={e => set({ severity: e.target.value })}
                className="w-full text-xs border border-gray-200 rounded-lg px-2 py-2 bg-white"
              >
                {["critical","high","medium","low","info"].map(s => (
                  <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider block mb-1">
                Confidence <span className="text-gray-400 normal-case font-normal">{form.confidence}%</span>
              </label>
              <input
                type="range" min={10} max={99} step={5}
                value={form.confidence}
                onChange={e => set({ confidence: parseInt(e.target.value) })}
                className="w-full accent-orange-500"
              />
            </div>
          </div>

          {/* Time window + Required count */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider block mb-1">Time Window</label>
              <select
                value={form.time_window_hours}
                onChange={e => set({ time_window_hours: parseInt(e.target.value) })}
                className="w-full text-xs border border-gray-200 rounded-lg px-2 py-2 bg-white"
              >
                {[1, 4, 6, 12, 24, 48, 72, 168].map(h => (
                  <option key={h} value={h}>{h}h {h >= 24 ? `(${h/24}d)` : ""}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider block mb-1">Min Matching Findings</label>
              <input
                type="number" min={1} max={50}
                value={form.required_count}
                onChange={e => set({ required_count: parseInt(e.target.value) || 1 })}
                className="w-full text-xs border border-gray-200 rounded-lg px-3 py-2"
              />
            </div>
          </div>

          {/* Conditions */}
          <div>
            <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider block mb-2">Conditions</label>
            <div className="border border-gray-200 rounded-xl p-3 bg-gray-50/50">
              <ConditionBuilder
                conditions={form.conditions}
                onChange={c => set({ conditions: c })}
              />
            </div>
          </div>

          {/* Tags */}
          <div>
            <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider block mb-1">Tags (comma-separated)</label>
            <input
              value={tagInput}
              onChange={e => setTagInput(e.target.value)}
              placeholder="fp-reduction, dev-machines, my-env"
              className="w-full text-xs border border-gray-200 rounded-lg px-3 py-2"
            />
          </div>

          {/* Recommendation */}
          <div>
            <label className="text-[9px] font-bold text-gray-500 uppercase tracking-wider block mb-1">Analyst Recommendation</label>
            <textarea
              value={form.recommendation}
              onChange={e => set({ recommendation: e.target.value })}
              rows={2}
              placeholder="Steps to take when this rule fires..."
              className="w-full text-xs border border-gray-200 rounded-lg px-3 py-2 resize-none"
            />
          </div>
        </div>

        {/* Footer */}
        <div className="sticky bottom-0 bg-gray-50 border-t border-gray-100 px-6 py-3 flex items-center justify-end gap-2">
          <button onClick={onCancel} className="px-3 py-1.5 text-xs text-gray-600 hover:text-gray-900 font-medium">
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={saving || !form.name.trim()}
            className="px-4 py-1.5 bg-orange-500 hover:bg-orange-600 text-white text-xs font-bold rounded-xl disabled:opacity-50 transition-all"
          >
            {saving ? "Saving…" : initial.id ? "Update Rule" : "Create Rule"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Test result panel ─────────────────────────────────────────────────────────

function TestPanel({ result }: { result: TestResult }) {
  return (
    <div className={cn(
      "p-3 rounded-xl border text-[10px]",
      result.would_fire ? "bg-orange-50 border-orange-200" : "bg-green-50 border-green-200"
    )}>
      <div className="flex items-center gap-2 font-bold mb-2">
        {result.would_fire
          ? <><AlertTriangle className="w-3.5 h-3.5 text-orange-500" /> Would fire — {result.matched_count} of {result.scanned} findings matched (need {result.required_count})</>
          : <><CheckCircle2 className="w-3.5 h-3.5 text-green-500" /> Would NOT fire — {result.matched_count} matched out of {result.scanned} (need {result.required_count})</>
        }
      </div>
      {result.matched_findings.length > 0 && (
        <div className="space-y-1 mt-1">
          {result.matched_findings.slice(0, 5).map(f => (
            <div key={f.id} className="flex items-center gap-1.5 text-[9px] text-gray-600">
              <SevDot sev={f.severity} />
              <span className="font-mono text-gray-400">#{f.id}</span>
              <span className="font-medium text-gray-700 truncate">{f.title}</span>
              <span className="ml-auto text-gray-400">{f.category}</span>
            </div>
          ))}
          {result.matched_findings.length > 5 && (
            <p className="text-gray-400 mt-1">+{result.matched_findings.length - 5} more…</p>
          )}
        </div>
      )}
    </div>
  );
}

// ── Rule Row ──────────────────────────────────────────────────────────────────

function RuleRow({
  rule,
  onEdit,
  onDelete,
  onToggle,
  onTest,
  testResult,
  testing,
}: {
  rule: CustomRule;
  onEdit: () => void;
  onDelete: () => void;
  onToggle: () => void;
  onTest: () => void;
  testResult: TestResult | null;
  testing: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const ac = ACTION_CONFIG[rule.action] ?? ACTION_CONFIG.alert;

  return (
    <div className={cn(
      "border rounded-xl transition-all",
      rule.enabled ? "border-gray-200 bg-white" : "border-gray-100 bg-gray-50/50"
    )}>
      {/* Main row */}
      <div className="flex items-center gap-2 px-4 py-3">
        {/* Enable toggle */}
        <button onClick={onToggle} className="flex-shrink-0 text-gray-300 hover:text-orange-500 transition-colors">
          {rule.enabled
            ? <ToggleRight className="w-4 h-4 text-orange-500" />
            : <ToggleLeft className="w-4 h-4" />}
        </button>

        {/* Sev dot */}
        <SevDot sev={rule.severity} />

        {/* Name */}
        <div className="flex-1 min-w-0">
          <div className={cn("text-[11px] font-bold truncate", rule.enabled ? "text-gray-800" : "text-gray-400")}>
            {rule.name}
          </div>
          {rule.description && (
            <div className="text-[9px] text-gray-400 truncate">{rule.description}</div>
          )}
        </div>

        {/* Action badge */}
        <span className={cn("flex items-center gap-1 px-1.5 py-0.5 rounded border text-[9px] font-bold flex-shrink-0", ac.cls)}>
          {ac.icon}{ac.label}
        </span>

        {/* Hit count */}
        {rule.hit_count > 0 && (
          <span className="text-[9px] text-gray-400 flex-shrink-0">
            {rule.hit_count} hits
          </span>
        )}

        {/* Condition count */}
        <span className="text-[9px] text-gray-400 flex-shrink-0">
          {rule.conditions?.rules?.length ?? 0} cond
        </span>

        {/* Confidence */}
        <span className="text-[9px] font-bold text-gray-500 flex-shrink-0">{rule.confidence}%</span>

        {/* Actions */}
        <div className="flex items-center gap-1 flex-shrink-0">
          <button
            onClick={onTest}
            disabled={testing}
            title="Test rule against active findings"
            className="p-1.5 rounded-lg hover:bg-green-50 text-gray-300 hover:text-green-600 transition-colors disabled:opacity-50"
          >
            <Play className="w-3 h-3" />
          </button>
          <button onClick={onEdit} className="p-1.5 rounded-lg hover:bg-blue-50 text-gray-300 hover:text-blue-600 transition-colors">
            <Edit2 className="w-3 h-3" />
          </button>
          <button onClick={onDelete} className="p-1.5 rounded-lg hover:bg-red-50 text-gray-300 hover:text-red-500 transition-colors">
            <Trash2 className="w-3 h-3" />
          </button>
          <button onClick={() => setExpanded(v => !v)} className="p-1.5 rounded-lg hover:bg-gray-100 text-gray-300 transition-colors">
            {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
        </div>
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="border-t border-gray-100 px-4 py-3 space-y-2 bg-gray-50/50 rounded-b-xl">
          {/* Conditions preview */}
          {rule.conditions?.rules?.length > 0 && (
            <div>
              <p className="text-[9px] font-bold text-gray-400 uppercase tracking-wider mb-1">Conditions ({rule.conditions.operator})</p>
              <div className="space-y-1">
                {rule.conditions.rules.map((c, i) => (
                  <div key={i} className="flex items-center gap-1.5 text-[9px] text-gray-600 bg-white border border-gray-100 rounded-lg px-2 py-1">
                    <span className="font-mono text-orange-500">{c.field}</span>
                    <span className="text-gray-400">{c.op}</span>
                    <span className="font-medium text-gray-700">{Array.isArray(c.value) ? c.value.join(", ") : String(c.value)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Meta */}
          <div className="flex items-center gap-4 text-[9px] text-gray-400">
            <span>Window: {rule.time_window_hours}h</span>
            <span>Min matches: {rule.required_count}</span>
            {rule.tags.length > 0 && (
              <span className="flex items-center gap-1">
                <Tag className="w-2.5 h-2.5" />
                {rule.tags.join(", ")}
              </span>
            )}
            <span className="ml-auto">
              Updated {new Date(rule.updated_at * 1000).toLocaleDateString()}
            </span>
          </div>

          {/* Test result */}
          {testResult && <TestPanel result={testResult} />}
          {testing && (
            <div className="flex items-center gap-2 text-[10px] text-gray-400">
              <RefreshCw className="w-3 h-3 animate-spin" />
              Running dry-run test…
            </div>
          )}

          {/* Recommendation */}
          {rule.recommendation && (
            <div className="flex items-start gap-1.5 text-[9px] text-gray-500 bg-blue-50 rounded-lg p-2">
              <Info className="w-3 h-3 text-blue-400 flex-shrink-0 mt-0.5" />
              {rule.recommendation}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function CustomCorrelationRules() {
  const [rules, setRules]         = useState<CustomRule[]>([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState<string | null>(null);
  const [showForm, setShowForm]   = useState(false);
  const [editRule, setEditRule]   = useState<Partial<CustomRule> | null>(null);
  const [saving, setSaving]       = useState(false);
  const [filter, setFilter]       = useState<"all" | "alert" | "suppress" | "elevate" | "tag">("all");
  const [testResults, setTestResults] = useState<Record<string, TestResult>>({});
  const [testing, setTesting]     = useState<Record<string, boolean>>({});

  const fetchRules = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiGet("/api/v1/custom-correlations");
      setRules(data.rules || []);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load rules");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchRules(); }, [fetchRules]);

  const handleSave = async (data: typeof BLANK_RULE) => {
    setSaving(true);
    try {
      if (editRule?.id) {
        await apiPut(`/api/v1/custom-correlations/${editRule.id}`, data);
      } else {
        await apiPost("/api/v1/custom-correlations", data);
      }
      setShowForm(false);
      setEditRule(null);
      await fetchRules();
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this rule? This cannot be undone.")) return;
    try {
      await apiDelete(`/api/v1/custom-correlations/${id}`);
      setRules(r => r.filter(x => x.id !== id));
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : "Delete failed");
    }
  };

  const handleToggle = async (id: string) => {
    try {
      const res = await apiPost(`/api/v1/custom-correlations/${id}/toggle`);
      setRules(r => r.map(x => x.id === id ? { ...x, enabled: res.enabled } : x));
    } catch { /* ignore */ }
  };

  const handleTest = async (id: string) => {
    setTesting(t => ({ ...t, [id]: true }));
    try {
      const res = await apiPost(`/api/v1/custom-correlations/${id}/test`);
      setTestResults(r => ({ ...r, [id]: res }));
    } catch { /* ignore */ }
    finally { setTesting(t => ({ ...t, [id]: false })); }
  };

  const filtered = filter === "all" ? rules : rules.filter(r => r.action === filter);
  const enabledCount = rules.filter(r => r.enabled).length;
  const suppressCount = rules.filter(r => r.action === "suppress").length;
  const alertCount = rules.filter(r => r.action === "alert").length;

  return (
    <div className="flex flex-col h-full bg-gray-50/30">
      {/* Header */}
      <div className="flex-shrink-0 bg-white border-b border-gray-100 px-6 py-4">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h1 className="text-base font-black text-gray-900 tracking-tight">Custom Correlation Rules</h1>
            <p className="text-[10px] text-gray-400 mt-0.5">
              Author detection and suppression rules tailored to your environment — reduces false positives and enhances coverage
            </p>
          </div>
          <button
            onClick={() => { setEditRule(null); setShowForm(true); }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-orange-500 hover:bg-orange-600 text-white text-[10px] font-bold rounded-xl transition-all"
          >
            <Plus className="w-3 h-3" /> New Rule
          </button>
        </div>

        {/* Stats row */}
        <div className="flex items-center gap-4 text-[10px] text-gray-500">
          <span className="font-bold text-gray-800">{rules.length}</span> total rules ·
          <span className="text-green-600 font-semibold">{enabledCount} enabled</span> ·
          <span className="text-orange-500 font-semibold">{alertCount} alert</span> ·
          <span className="text-gray-500 font-semibold">{suppressCount} suppress</span>
        </div>

        {/* Filter tabs */}
        <div className="flex items-center gap-1 mt-3">
          <Filter className="w-3 h-3 text-gray-300 mr-1" />
          {(["all", "alert", "suppress", "elevate", "tag"] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn(
                "px-2.5 py-1 rounded-lg text-[9px] font-bold border transition-all",
                filter === f
                  ? "bg-orange-500 text-white border-orange-500"
                  : "bg-white text-gray-500 border-gray-200 hover:border-orange-200"
              )}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
          <button
            onClick={fetchRules}
            className="ml-auto p-1.5 rounded-lg hover:bg-gray-100 text-gray-300 hover:text-gray-600 transition-colors"
            title="Refresh"
          >
            <RefreshCw className={cn("w-3 h-3", loading && "animate-spin")} />
          </button>
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto px-6 py-4">
        {loading ? (
          <div className="flex items-center justify-center py-20 text-[10px] text-gray-400">
            <RefreshCw className="w-4 h-4 animate-spin mr-2" /> Loading rules…
          </div>
        ) : error ? (
          <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-xl text-[10px] text-red-600">
            <XCircle className="w-3.5 h-3.5 flex-shrink-0" /> {error}
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <Shield className="w-8 h-8 text-gray-200 mb-3" />
            <p className="text-sm font-semibold text-gray-400">
              {filter === "all" ? "No custom rules yet" : `No ${filter} rules`}
            </p>
            <p className="text-[10px] text-gray-300 mt-1 max-w-sm">
              {filter === "all"
                ? "Create your first rule to reduce false positives or detect environment-specific patterns"
                : `Switch filter to "all" or create a new ${filter} rule`}
            </p>
            {filter === "all" && (
              <button
                onClick={() => { setEditRule(null); setShowForm(true); }}
                className="mt-4 flex items-center gap-1.5 px-3 py-1.5 bg-orange-500 text-white text-[10px] font-bold rounded-xl"
              >
                <Plus className="w-3 h-3" /> Create First Rule
              </button>
            )}
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.map(rule => (
              <RuleRow
                key={rule.id}
                rule={rule}
                onEdit={() => { setEditRule(rule); setShowForm(true); }}
                onDelete={() => handleDelete(rule.id)}
                onToggle={() => handleToggle(rule.id)}
                onTest={() => handleTest(rule.id)}
                testResult={testResults[rule.id] ?? null}
                testing={testing[rule.id] ?? false}
              />
            ))}
          </div>
        )}

        {/* Info box */}
        {rules.length === 0 && !loading && !error && (
          <div className="mt-4 p-4 bg-blue-50 border border-blue-100 rounded-xl text-[10px] text-blue-700">
            <p className="font-bold mb-1">How custom rules work</p>
            <ul className="space-y-0.5 text-blue-600 list-disc list-inside">
              <li><strong>Alert</strong> — creates a correlation incident when conditions are met</li>
              <li><strong>Suppress</strong> — automatically marks matching findings as false positive</li>
              <li><strong>Elevate</strong> — raises severity of matching findings to critical</li>
              <li><strong>Tag</strong> — appends custom tags to matching findings for routing</li>
            </ul>
            <p className="mt-2 text-blue-500">Rules are evaluated every correlation cycle (every few minutes per agent). Use the Test button to dry-run against current findings before enabling.</p>
          </div>
        )}
      </div>

      {/* Form modal */}
      {showForm && (
        <RuleForm
          initial={editRule ?? {}}
          onSave={handleSave}
          onCancel={() => { setShowForm(false); setEditRule(null); }}
          saving={saving}
        />
      )}
    </div>
  );
}
