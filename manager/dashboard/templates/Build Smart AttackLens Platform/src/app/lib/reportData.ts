import type { Col } from "./exportUtils";

export const INCIDENT_COLS: Col[] = [
  { key: "finding_id", header: "Finding ID" },
  { key: "finding_uid", header: "Finding UID" },
  { key: "external_id", header: "External ID" },
  { key: "asset_agent_id", header: "Agent ID" },
  { key: "asset_hostname", header: "Hostname" },
  { key: "first_detected_at", header: "First Detected" },
  { key: "last_detected_at", header: "Last Detected" },
  { key: "incident_title", header: "Incident" },
  { key: "category", header: "Category" },
  { key: "terrain", header: "Terrain" },
  { key: "severity", header: "Severity" },
  { key: "status", header: "Status" },
  { key: "description", header: "Description" },
  { key: "business_impact", header: "Business Impact" },
  { key: "confidence_pct", header: "Confidence %" },
  { key: "validation_score_pct", header: "Validation Score %" },
  { key: "source", header: "Source" },
  { key: "rule_id", header: "Rule ID" },
  { key: "mitre_tactic", header: "MITRE Tactic" },
  { key: "mitre_technique", header: "MITRE Technique" },
  { key: "cve_ids", header: "CVE IDs" },
  { key: "cvss_score", header: "CVSS" },
  { key: "kev", header: "KEV" },
  { key: "exploit_available", header: "Exploit Available" },
  { key: "ai_verdict", header: "AI Verdict" },
  { key: "ai_confidence_pct", header: "AI Confidence %" },
  { key: "ai_reasoning", header: "AI Reasoning" },
  { key: "remediation", header: "Remediation" },
  { key: "actions_performed", header: "Actions" },
  { key: "scan_count", header: "Scan Count" },
  { key: "evidence", header: "Evidence (JSON)" },
];

export const TIMELINE_COLS: Col[] = [
  { key: "finding_id", header: "Finding ID" },
  { key: "finding_uid", header: "Finding UID" },
  { key: "incident_title", header: "Incident" },
  { key: "severity", header: "Severity" },
  { key: "terrain", header: "Terrain" },
  { key: "event_time", header: "Event Time" },
  { key: "elapsed", header: "Elapsed" },
  { key: "source", header: "Source" },
  { key: "actor", header: "Actor" },
  { key: "action", header: "Action" },
  { key: "from_status", header: "From Status" },
  { key: "to_status", header: "To Status" },
  { key: "note", header: "Note" },
  { key: "changed_fields", header: "Changed Fields" },
  { key: "metadata", header: "Metadata" },
];

export const TELEMETRY_COLS: Col[] = [
  { key: "timestamp", header: "Timestamp" },
  { key: "agent_id", header: "Agent ID" },
  { key: "agent_name", header: "Agent Name" },
  { key: "section", header: "Section" },
  { key: "record_count", header: "Records" },
  { key: "ingest_lag_s", header: "Ingest Lag (s)" },
  { key: "data", header: "Data (JSON)" },
];

export const SUMMARY_COLS: Col[] = [
  { key: "field", header: "Field" },
  { key: "value", header: "Value" },
];

const iso = (epochOrIso: unknown): string => {
  if (epochOrIso == null || epochOrIso === "") return "";
  if (typeof epochOrIso === "number") return new Date(epochOrIso * 1000).toISOString();
  const n = Number(epochOrIso);
  if (!Number.isNaN(n) && String(epochOrIso).trim() !== "" && n > 1_000_000_000) {
    return new Date(n * 1000).toISOString();
  }
  return String(epochOrIso);
};
const yesno = (b: unknown): string => (b ? "Yes" : "No");
const joinArr = (v: unknown, sep = "; "): string =>
  Array.isArray(v)
    ? v.map((x) => (typeof x === "object" ? JSON.stringify(x) : String(x))).join(sep)
    : v == null
      ? ""
      : String(v);

export function mapIncident(f: any): Record<string, unknown> {
  const ai = f.ai_verdict || {};
  return {
    finding_id: f.id,
    finding_uid: f.finding_uid ?? "",
    external_id: f.external_id ?? "",
    asset_agent_id: f.agent_id ?? "",
    asset_hostname: f.agent_hostname ?? "",
    first_detected_at: iso(f.first_detected_at),
    last_detected_at: iso(f.last_detected_at),
    incident_title: f.title ?? "",
    category: f.category ?? "",
    terrain: f.terrain ?? "",
    severity: f.severity ?? "",
    status: f.status ?? "",
    description: f.description ?? "",
    business_impact: f.impact ?? "",
    confidence_pct: f.confidence_pct ?? "",
    validation_score_pct: typeof f.precision_score === "number" ? Math.round(f.precision_score * 100) : "",
    source: f.source ?? "",
    rule_id: f.rule_id ?? "",
    mitre_tactic: f.mitre_tactic ?? "",
    mitre_technique: f.mitre_technique ?? "",
    cve_ids: joinArr(f.cve_ids, ", "),
    cvss_score: f.cvss_score ?? "",
    kev: yesno(f.kev),
    exploit_available: yesno(f.exploit_available),
    ai_verdict: ai.label ?? "",
    ai_confidence_pct: typeof ai.confidence === "number" ? Math.round(ai.confidence * 100) : "",
    ai_reasoning: ai.reasoning ?? "",
    remediation: joinArr(f.action_plan),
    actions_performed: joinArr(f.available_actions),
    scan_count: f.scan_count ?? "",
    evidence: f.evidence ? JSON.stringify(f.evidence) : "",
  };
}

export function mapTimelineEvent(ev: any, f: any): Record<string, unknown> {
  return {
    finding_id: f.id,
    finding_uid: f.finding_uid ?? ev.finding_uid ?? "",
    incident_title: f.title ?? "",
    severity: f.severity ?? "",
    terrain: f.terrain ?? "",
    event_time: iso(ev.created_at),
    elapsed: ev.elapsed ?? "",
    source: ev.source ?? "",
    actor: ev.actor ?? "",
    action: ev.action ?? "",
    from_status: ev.from_status ?? "",
    to_status: ev.to_status ?? "",
    note: ev.note ?? "",
    changed_fields: ev.changed_fields ? JSON.stringify(ev.changed_fields) : "",
    metadata: ev.metadata ? JSON.stringify(ev.metadata) : "",
  };
}

export function mapTelemetry(row: any, agentName: (id: string) => string): Record<string, unknown> {
  const collected = Number(row.collected_at) || 0;
  const received = Number(row.received_at) || 0;
  return {
    timestamp: iso(row.collected_at),
    agent_id: row.agent_id ?? "",
    agent_name: agentName(row.agent_id ?? ""),
    section: row.section ?? "",
    record_count: row.record_count ?? "",
    ingest_lag_s: received && collected ? Math.max(0, Math.round(received - collected)) : "",
    data: row.data ? JSON.stringify(row.data) : "",
  };
}

export function buildSummary(
  incidents: any[],
  timelineCount: number,
  deepRows: number,
  meshRows: number,
  windowLabel: string,
  filters: string,
): Record<string, unknown>[] {
  const by = (key: string) =>
    incidents.reduce<Record<string, number>>((acc, f) => {
      const k = String(f[key] ?? "unknown");
      acc[k] = (acc[k] || 0) + 1;
      return acc;
    }, {});
  const fmt = (o: Record<string, number>) => Object.entries(o).map(([k, v]) => `${k}: ${v}`).join(", ");
  return [
    { field: "Generated At", value: new Date().toISOString() },
    { field: "Platform", value: "AttackLens" },
    { field: "Time Window", value: windowLabel },
    { field: "Filters Applied", value: filters || "none" },
    { field: "Total Incidents", value: incidents.length },
    { field: "Incidents by Severity", value: fmt(by("severity")) },
    { field: "Incidents by Terrain", value: fmt(by("terrain")) },
    { field: "Incidents by Status", value: fmt(by("status")) },
    { field: "Total Timeline Events", value: timelineCount },
    { field: "Deep Analysis Rows", value: deepRows },
    { field: "DeepMesh Rows", value: meshRows },
  ];
}

/**
 * Paginate a list endpoint to exhaustion. Handles the shapes used across the
 * dashboard: a bare array, or an object with items/findings/rows plus a
 * next cursor or total count. Verify the exact param/stop-condition against
 * pages/Incidents.tsx and pages/analysis/deep/index.tsx before relying on it.
 */
export async function fetchAllPages(url: string): Promise<any[]> {
  const out: any[] = [];
  let page = 1;
  for (;;) {
    const u = new URL(url, window.location.origin);
    u.searchParams.set("page", String(page));
    const res = await fetch(u.toString());
    if (!res.ok) throw new Error(`${u.pathname} → ${res.status}`);
    const body = await res.json();
    const items = Array.isArray(body) ? body : body.items || body.findings || body.rows || [];
    out.push(...items);
    const hasMore = !Array.isArray(body) && (body.next || (body.total && out.length < body.total));
    if (!items.length || !hasMore) break;
    page += 1;
  }
  return out;
}

/**
 * Fetch per-incident timelines with a bounded worker pool. A single failed
 * timeline degrades that incident to an empty list; it never aborts the export.
 */
export async function fetchTimelines(
  ids: number[],
  opts: { concurrency?: number; onProgress?: (done: number, total: number) => void } = {},
): Promise<Map<number, any[]>> {
  const concurrency = opts.concurrency ?? 6;
  const result = new Map<number, any[]>();
  let done = 0;
  let i = 0;
  async function worker() {
    while (i < ids.length) {
      const id = ids[i++];
      try {
        const res = await fetch(`/api/v1/findings/${id}/timeline`);
        const body = res.ok ? await res.json() : { timeline: [] };
        result.set(id, body.timeline || []);
      } catch {
        result.set(id, []);
      }
      done += 1;
      opts.onProgress?.(done, ids.length);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, ids.length) }, worker));
  return result;
}

/** Route a large export to the streaming backend endpoint (Phase B). */
export function serverExport(
  type: "all" | "incident" | "telemetry",
  format: "xlsx" | "csv",
  params: URLSearchParams,
): void {
  const u = new URL("/api/v1/reports/export", window.location.origin);
  u.searchParams.set("type", type);
  u.searchParams.set("format", format);
  params.forEach((v, k) => u.searchParams.set(k, v));
  window.location.href = u.toString();
}
