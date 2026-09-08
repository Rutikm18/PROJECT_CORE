# Reports Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Reports page that exports Deep Analysis + DeepMesh telemetry and all incidents (with evidence, scores, remediation, actions, and full timeline history) as one multi-sheet `.xlsx` (or per-sheet CSV) — client-side first (Phase A), then a streaming backend endpoint (Phase B).

**Architecture:** Phase A assembles the workbook in the browser by reusing existing read APIs (`/detection/all`, `/raw/query`, per-incident `/findings/{id}/timeline`) via SheetJS. Phase B adds `GET /api/v1/reports/export`, which does the same joins in SQL (no N+1) and streams the file; the front-end routes large exports to it. Both phases emit the identical 5-sheet workbook (Summary, Incidents, Timeline, Deep Analysis, DeepMesh).

**Tech Stack:** React + TypeScript + Vite (front-end app root: `manager/dashboard/templates/Build Smart AttackLens Platform/`), Vitest; SheetJS (`xlsx`); FastAPI + Python, pytest; `xlsxwriter` (Phase B).

## Global Constraints

- Front-end app root (all `src/app/...` paths below are relative to it): `manager/dashboard/templates/Build Smart AttackLens Platform/` — the directory name contains spaces; always quote it.
- API calls use the global `fetch` (credentials are injected by `installApiFetch()` in `lib/apiFetch.ts`) — do **not** add a new HTTP client.
- Time windows come from `lib/timeRange.ts`: `rangeToParams(r: TimeRange): URLSearchParams`, `WindowKey`, `TimeRange`, `DEFAULT_RANGE`.
- Vite `base: '/static/'`, `build.outDir: '../../static'` — `npm run build` regenerates `manager/dashboard/static/`, which the manager serves; committing the built `static/` is how front-end changes deploy.
- The 5 sheets and their exact columns are defined in `docs/superpowers/specs/2026-09-08-reports-export-design.md` §3 — copy column keys verbatim.
- Incident `evidence` arrives from `/api/v1/detection/all` already parsed as a dict; JSON-stringify it for the cell.
- Timeline event fields (from `/api/v1/findings/{id}/timeline`): `source`, `actor`, `action`, `from_status`, `to_status`, `note`, `created_at` (epoch seconds), `elapsed`, `changed_fields`, `metadata`, `finding_uid`.
- Backend endpoint must be `require_session`-guarded and tenant-scoped, matching sibling routers in `manager/manager/api/`.

---

## PHASE A — Client-side export

### Task A1: `xlsx` dependency + `exportUtils.ts`

**Files:**
- Modify: `manager/dashboard/templates/Build Smart AttackLens Platform/package.json` (add `xlsx`)
- Create: `src/app/lib/exportUtils.ts`
- Test: `src/app/lib/exportUtils.test.ts`

**Interfaces:**
- Produces:
  - `type Col = { key: string; header: string }`
  - `type Sheet = { name: string; rows: Record<string, unknown>[]; cols: Col[]; severityKey?: string }`
  - `toCSV(rows: Record<string, unknown>[], cols: Col[]): string`
  - `toXLSX(sheets: Sheet[], filename: string): void` (triggers a browser download)
  - `downloadText(text: string, filename: string, mime: string): void`

- [ ] **Step 1: Install the dependency**

Run (quote the path):
```bash
cd "manager/dashboard/templates/Build Smart AttackLens Platform" && npm install xlsx
```
Expected: `package.json` gains `"xlsx": "^0.18.x"` under dependencies; `package-lock.json` updates.

- [ ] **Step 2: Write the failing test**

Create `src/app/lib/exportUtils.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import { toCSV } from "./exportUtils";

describe("toCSV", () => {
  const cols = [
    { key: "id", header: "ID" },
    { key: "note", header: "Note" },
  ];
  it("emits a header row then one row per record, in column order", () => {
    const csv = toCSV([{ id: 1, note: "ok" }], cols);
    expect(csv).toBe('ID,Note\r\n1,ok');
  });
  it("quotes and escapes commas, quotes, and newlines", () => {
    const csv = toCSV([{ id: 1, note: 'a,"b"\nc' }], cols);
    expect(csv).toBe('ID,Note\r\n1,"a,""b""\nc"');
  });
  it("renders missing/undefined as empty and JSON-stringifies objects", () => {
    const csv = toCSV([{ id: 2, note: { k: 1 } }], cols);
    expect(csv).toBe('ID,Note\r\n2,"{""k"":1}"');
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd "manager/dashboard/templates/Build Smart AttackLens Platform" && npx vitest run src/app/lib/exportUtils.test.ts`
Expected: FAIL — cannot resolve `./exportUtils`.

- [ ] **Step 4: Implement `exportUtils.ts`**

Create `src/app/lib/exportUtils.ts`:
```ts
import * as XLSX from "xlsx";

export type Col = { key: string; header: string };
export type Sheet = {
  name: string;
  rows: Record<string, unknown>[];
  cols: Col[];
  severityKey?: string; // column key used to colour Excel rows
};

function cell(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function csvField(s: string): string {
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCSV(rows: Record<string, unknown>[], cols: Col[]): string {
  const head = cols.map((c) => csvField(c.header)).join(",");
  const body = rows.map((r) => cols.map((c) => csvField(cell(r[c.key]))).join(",")).join("\r\n");
  return body ? `${head}\r\n${body}` : head;
}

export function downloadText(text: string, filename: string, mime: string): void {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function toXLSX(sheets: Sheet[], filename: string): void {
  const wb = XLSX.utils.book_new();
  for (const s of sheets) {
    const aoa = [s.cols.map((c) => c.header), ...s.rows.map((r) => s.cols.map((c) => cell(r[c.key])))];
    const ws = XLSX.utils.aoa_to_sheet(aoa);
    ws["!freeze"] = { xSplit: 0, ySplit: 1 };
    ws["!cols"] = s.cols.map((c) => {
      const max = Math.max(c.header.length, ...s.rows.map((r) => cell(r[c.key]).length));
      return { wch: Math.min(60, Math.max(10, max + 2)) };
    });
    XLSX.utils.book_append_sheet(wb, ws, s.name.slice(0, 31));
  }
  XLSX.writeFile(wb, filename);
}
```
(Note: SheetJS community edition does not apply cell fills; severity colouring is best-effort and may be dropped here — the Phase B `xlsxwriter` path applies real fills. Keep `severityKey` in the type for Phase B parity.)

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run src/app/lib/exportUtils.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add "manager/dashboard/templates/Build Smart AttackLens Platform/package.json" "manager/dashboard/templates/Build Smart AttackLens Platform/package-lock.json" "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/lib/exportUtils.ts" "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/lib/exportUtils.test.ts"
git commit -m "feat(reports): xlsx dep + exportUtils (multi-sheet CSV/XLSX)"
```

---

### Task A2: `reportData.ts` — column defs, row mappers, fetchers, timeline pool

**Files:**
- Create: `src/app/lib/reportData.ts`
- Test: `src/app/lib/reportData.test.ts`

**Interfaces:**
- Consumes: `Col`, `Sheet` from `exportUtils`; `rangeToParams`, `TimeRange` from `timeRange`.
- Produces:
  - `INCIDENT_COLS: Col[]`, `TIMELINE_COLS: Col[]`, `TELEMETRY_COLS: Col[]`, `SUMMARY_COLS: Col[]`
  - `mapIncident(f: any): Record<string, unknown>`
  - `mapTimelineEvent(ev: any, f: any): Record<string, unknown>`
  - `mapTelemetry(row: any, agentName: (id: string) => string): Record<string, unknown>`
  - `buildSummary(incidents: any[], timelineCount: number, deepRows: number, meshRows: number, windowLabel: string, filters: string): Record<string, unknown>[]`
  - `fetchAllPages(url: string): Promise<any[]>`
  - `fetchTimelines(ids: number[], opts: { concurrency?: number; onProgress?: (done: number, total: number) => void }): Promise<Map<number, any[]>>`

- [ ] **Step 1: Write the failing test (pure mappers)**

Create `src/app/lib/reportData.test.ts`:
```ts
import { describe, it, expect } from "vitest";
import { mapIncident, mapTimelineEvent, INCIDENT_COLS, TIMELINE_COLS } from "./reportData";

describe("mapIncident", () => {
  it("flattens evidence + ai_verdict + score into the incident columns", () => {
    const row = mapIncident({
      id: 7, finding_uid: "u7", title: "Suspicious binary", terrain: "citadels",
      severity: "high", status: "new", precision_score: 0.9, confidence_pct: 82,
      action_plan: ["isolate host"], available_actions: ["quarantine", "notify"],
      evidence: { path: "/tmp/x", _source: "edr" },
      ai_verdict: { label: "tp", confidence: 0.88, reasoning: "matches TTP" },
      cve_ids: ["CVE-2024-1"], kev: true, exploit_available: false,
    });
    expect(row.finding_id).toBe(7);
    expect(row.incident_title).toBe("Suspicious binary");
    expect(row.validation_score_pct).toBe(90);
    expect(row.remediation).toBe("isolate host");
    expect(row.actions_performed).toBe("quarantine; notify");
    expect(row.ai_verdict).toBe("tp");
    expect(row.ai_confidence_pct).toBe(88);
    expect(row.cve_ids).toBe("CVE-2024-1");
    expect(row.kev).toBe("Yes");
    expect(row.exploit_available).toBe("No");
    expect(JSON.parse(String(row.evidence)).path).toBe("/tmp/x");
    // every declared column key exists on the mapped row
    for (const c of INCIDENT_COLS) expect(c.key in row).toBe(true);
  });
});

describe("mapTimelineEvent", () => {
  it("joins the incident context and converts epoch to ISO", () => {
    const row = mapTimelineEvent(
      { source: "case", actor: "alice", action: "status_change", from_status: "new", to_status: "triaging", note: "n", created_at: 1700000000 },
      { id: 7, finding_uid: "u7", title: "T", severity: "high", terrain: "citadels" },
    );
    expect(row.finding_id).toBe(7);
    expect(row.actor).toBe("alice");
    expect(row.event_time).toBe(new Date(1700000000 * 1000).toISOString());
    for (const c of TIMELINE_COLS) expect(c.key in row).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/app/lib/reportData.test.ts`
Expected: FAIL — cannot resolve `./reportData`.

- [ ] **Step 3: Implement `reportData.ts`**

Create `src/app/lib/reportData.ts`:
```ts
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
  if (!Number.isNaN(n) && String(epochOrIso).trim() !== "" && n > 1_000_000_000) return new Date(n * 1000).toISOString();
  return String(epochOrIso);
};
const yesno = (b: unknown): string => (b ? "Yes" : "No");
const joinArr = (v: unknown, sep = "; "): string =>
  Array.isArray(v) ? v.map((x) => (typeof x === "object" ? JSON.stringify(x) : String(x))).join(sep) : v == null ? "" : String(v);

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
  incidents: any[], timelineCount: number, deepRows: number, meshRows: number, windowLabel: string, filters: string,
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

// Follows the paginated shape of /detection/all and /raw/query: each page
// returns { items: [...], next?: <cursor|page> }. Adjust the page param to match
// the sibling pages (see pages/Incidents.tsx and pages/analysis/deep/index.tsx).
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

export async function fetchTimelines(
  ids: number[], opts: { concurrency?: number; onProgress?: (done: number, total: number) => void } = {},
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
        result.set(id, []); // a single failure never aborts the export
      }
      done += 1;
      opts.onProgress?.(done, ids.length);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, ids.length) }, worker));
  return result;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run src/app/lib/reportData.test.ts`
Expected: PASS.

- [ ] **Step 5: Verify pagination/cursor shape against the real APIs**

Read `src/app/pages/Incidents.tsx` and `src/app/pages/analysis/deep/index.tsx`; confirm how they page `/detection/all` and `/raw/query` (param name + stop condition). If they differ from `page`/`next`/`total`, adjust `fetchAllPages` accordingly and re-run the test. Commit only after the mapper tests still pass.

- [ ] **Step 6: Commit**

```bash
git add "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/lib/reportData.ts" "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/lib/reportData.test.ts"
git commit -m "feat(reports): report column defs, row mappers, paginated fetchers + timeline pool"
```

---

### Task A3: `Reports.tsx` page

**Files:**
- Create: `src/app/pages/Reports.tsx`
- Test: `src/app/pages/Reports.render.test.tsx`

**Interfaces:**
- Consumes: `toCSV`, `toXLSX`, `Sheet` (exportUtils); all exports of `reportData`; `rangeToParams`, `DEFAULT_RANGE`, `WindowKey` (timeRange).
- Produces: `default` React component `Reports`.

- [ ] **Step 1: Implement the page**

Create `src/app/pages/Reports.tsx`. Mirror the header/card/tab/filter-bar classes from `src/app/pages/ThreatIntelligence.tsx` (tabs) and `src/app/pages/analysis/deep/index.tsx` (filter chips) so it matches the product. Structure:
```tsx
import { useState } from "react";
import { FileText, Download, Loader2 } from "lucide-react";
import { toCSV, toXLSX, downloadText, type Sheet } from "../lib/exportUtils";
import {
  INCIDENT_COLS, TIMELINE_COLS, TELEMETRY_COLS, SUMMARY_COLS,
  mapIncident, mapTimelineEvent, mapTelemetry, buildSummary,
  fetchAllPages, fetchTimelines,
} from "../lib/reportData";
import { rangeToParams, DEFAULT_RANGE } from "../lib/timeRange";

type Tab = "telemetry" | "incident" | "full";

export default function Reports() {
  const [tab, setTab] = useState<Tab>("telemetry");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState("");
  const [error, setError] = useState("");

  async function agentNameMap(): Promise<(id: string) => string> {
    try {
      const res = await fetch("/api/v1/raw/agents");
      const list = res.ok ? await res.json() : [];
      const m = new Map<string, string>((Array.isArray(list) ? list : list.items || []).map((a: any) => [a.agent_id ?? a.id, a.name ?? a.hostname ?? a.agent_id]));
      return (id: string) => m.get(id) ?? id;
    } catch { return (id: string) => id; }
  }

  async function gatherTelemetry(section?: string) {
    const params = rangeToParams(DEFAULT_RANGE);
    if (section) params.set("section", section);
    const rows = await fetchAllPages(`/api/v1/raw/query?${params.toString()}`);
    const nameOf = await agentNameMap();
    return rows.map((r) => mapTelemetry(r, nameOf));
  }

  async function gatherIncidents() {
    const findings = await fetchAllPages(`/api/v1/detection/all?${rangeToParams(DEFAULT_RANGE).toString()}`);
    const incidents = findings.map(mapIncident);
    setProgress(`Fetching timeline 0/${findings.length}…`);
    const timelines = await fetchTimelines(findings.map((f) => f.id), {
      onProgress: (d, t) => setProgress(`Fetching timeline ${d}/${t}…`),
    });
    const timelineRows = findings.flatMap((f) => (timelines.get(f.id) || []).map((ev) => mapTimelineEvent(ev, f)));
    return { findings, incidents, timelineRows };
  }

  async function run(kind: Tab, fmt: "csv" | "xlsx") {
    setBusy(true); setError(""); setProgress("Fetching…");
    try {
      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      if (kind === "telemetry") {
        const deep = await gatherTelemetry();
        const mesh = await gatherTelemetry("developer_security");
        const sheets: Sheet[] = [
          { name: "Deep Analysis", rows: deep, cols: TELEMETRY_COLS },
          { name: "DeepMesh (AI Security)", rows: mesh, cols: TELEMETRY_COLS },
        ];
        emit(sheets, fmt, `attacklens-telemetry-${ts}`);
      } else if (kind === "incident") {
        const { incidents, timelineRows } = await gatherIncidents();
        const sheets: Sheet[] = [
          { name: "Incidents", rows: incidents, cols: INCIDENT_COLS, severityKey: "severity" },
          { name: "Timeline", rows: timelineRows, cols: TIMELINE_COLS },
        ];
        emit(sheets, fmt, `attacklens-incidents-${ts}`);
      } else {
        const deep = await gatherTelemetry();
        const mesh = await gatherTelemetry("developer_security");
        const { findings, incidents, timelineRows } = await gatherIncidents();
        const summary = buildSummary(findings, timelineRows.length, deep.length, mesh.length, "24h", "none");
        const sheets: Sheet[] = [
          { name: "Summary", rows: summary, cols: SUMMARY_COLS },
          { name: "Incidents", rows: incidents, cols: INCIDENT_COLS, severityKey: "severity" },
          { name: "Timeline", rows: timelineRows, cols: TIMELINE_COLS },
          { name: "Deep Analysis", rows: deep, cols: TELEMETRY_COLS },
          { name: "DeepMesh (AI Security)", rows: mesh, cols: TELEMETRY_COLS },
        ];
        emit(sheets, fmt, `attacklens-report-${ts}`);
      }
    } catch (e: any) {
      setError(`Export failed: ${e?.message || e}. Try again.`);
    } finally {
      setBusy(false); setProgress("");
    }
  }

  function emit(sheets: Sheet[], fmt: "csv" | "xlsx", base: string) {
    if (fmt === "xlsx") { toXLSX(sheets, `${base}.xlsx`); return; }
    for (const s of sheets) downloadText(toCSV(s.rows, s.cols), `${base}-${s.name.replace(/\W+/g, "_")}.csv`, "text/csv");
  }

  return (
    <div className="p-6">
      <div className="rounded-2xl shadow-card bg-white border-t-[3px] border-indigo-500 p-5 mb-4 flex items-center gap-3">
        <FileText className="text-indigo-600" />
        <h1 className="text-lg font-semibold">Reports</h1>
      </div>
      <div className="flex gap-2 mb-4">
        {(["telemetry", "incident", "full"] as Tab[]).map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-xl text-sm font-semibold ${tab === t ? "bg-white shadow-card" : "bg-slate-100 text-slate-600"}`}>
            {t === "telemetry" ? "Telemetry Export" : t === "incident" ? "Incident Report" : "Full Report"}
          </button>
        ))}
      </div>
      {error && <div className="mb-3 rounded-xl bg-red-50 text-red-700 px-4 py-2 text-sm">{error}</div>}
      <div className="flex gap-3">
        <button disabled={busy} onClick={() => run(tab, "xlsx")}
          className="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-60 text-white rounded-xl px-4 py-2 text-sm font-semibold">
          {busy ? <Loader2 className="animate-spin size-4" /> : <Download className="size-4" />} Download Excel (.xlsx)
        </button>
        <button disabled={busy} onClick={() => run(tab, "csv")}
          className="inline-flex items-center gap-2 border border-slate-300 hover:bg-slate-50 disabled:opacity-60 rounded-xl px-4 py-2 text-sm font-semibold">
          <Download className="size-4" /> Download CSV
        </button>
        {busy && <span className="text-sm text-slate-500 self-center">{progress}</span>}
      </div>
    </div>
  );
}
```
(Filter bars — time window, agent, sections, terrain/severity/status — are additive; wire them exactly like `analysis/deep/index.tsx` and `Incidents.tsx` and pass the chosen params into `gatherTelemetry`/`gatherIncidents` in place of `DEFAULT_RANGE`. Ship the working defaults above first, then layer filters.)

- [ ] **Step 2: Write a render test**

Create `src/app/pages/Reports.render.test.tsx`:
```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import Reports from "./Reports";

describe("Reports page", () => {
  it("renders tabs and export buttons", () => {
    render(<Reports />);
    expect(screen.getByText("Telemetry Export")).toBeTruthy();
    expect(screen.getByText("Incident Report")).toBeTruthy();
    expect(screen.getByText(/Download Excel/)).toBeTruthy();
  });
});
```

- [ ] **Step 3: Run tests**

Run: `npx vitest run src/app/pages/Reports.render.test.tsx`
Expected: PASS. (If the repo has no `@testing-library/react`, match whatever the sibling `*.render.test.tsx` files use, e.g. `terrainPages.render.test.tsx`.)

- [ ] **Step 4: Commit**

```bash
git add "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/pages/Reports.tsx" "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/pages/Reports.render.test.tsx"
git commit -m "feat(reports): Reports page (telemetry / incident / full workbook export)"
```

---

### Task A4: Wire the route + sidebar, build the bundle

**Files:**
- Modify: `src/app/router/index.tsx` (lazy import + route)
- Modify: `src/app/components/Sidebar.tsx` (nav item)
- Modify: `src/app/pages/_routes.ts` (doc/map entry)

- [ ] **Step 1: Register the lazy route**

In `src/app/router/index.tsx`, next to the other `lazy` imports add:
```tsx
const Reports = lazy(() => import("../pages/Reports"));
```
and add a child route under the authenticated `AppShell` children, alongside `analysis/deep`:
```tsx
{ path: "reports", element: <Suspense fallback={null}><Reports /></Suspense> },
```
(Match the exact `<Suspense>`/guard wrapper the neighbouring routes use.)

- [ ] **Step 2: Add the sidebar item**

In `src/app/components/Sidebar.tsx`, in the "Inventory & Analysis" group, below the DeepMesh entry, add an item pointing to `/reports` with the `FileText` icon — copy the exact shape of the adjacent items in that array.

- [ ] **Step 3: Update the route map doc**

In `src/app/pages/_routes.ts`, add a `/reports → pages/Reports.tsx  Reports` line in the comment block near `/analysis/deep`.

- [ ] **Step 4: Typecheck + build**

Run:
```bash
cd "manager/dashboard/templates/Build Smart AttackLens Platform" && npm run build
```
Expected: build succeeds, emits into `../../static/` (i.e. `manager/dashboard/static/`).

- [ ] **Step 5: Commit source + built bundle**

```bash
git add "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/router/index.tsx" "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/components/Sidebar.tsx" "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/pages/_routes.ts" manager/dashboard/static
git commit -m "feat(reports): route + sidebar wiring, rebuild dashboard bundle"
```

---

## PHASE B — Backend export endpoint

### Task B1: `reports.py` pure row-assembly helpers

**Files:**
- Create: `manager/manager/api/reports.py`
- Test: `manager/tests/unit/test_reports_export.py`

**Interfaces:**
- Produces (module-level, pure — no I/O):
  - `INCIDENT_COLUMNS: list[tuple[str, str]]` (key, header) — same keys as `INCIDENT_COLS`
  - `TIMELINE_COLUMNS`, `TELEMETRY_COLUMNS`, `SUMMARY_COLUMNS`
  - `incident_row(f: dict) -> dict`
  - `timeline_row(ev: dict, f: dict) -> dict`
  - `summary_rows(incidents: list[dict], timeline_count: int, deep: int, mesh: int, window: str, filters: str) -> list[dict]`

- [ ] **Step 1: Write the failing test**

Create `manager/tests/unit/test_reports_export.py`:
```python
from manager.api.reports import incident_row, timeline_row, INCIDENT_COLUMNS

def test_incident_row_flattens_score_actions_and_evidence():
    row = incident_row({
        "id": 7, "finding_uid": "u7", "title": "Bad binary", "terrain": "citadels",
        "severity": "high", "status": "new", "precision_score": 0.9,
        "action_plan": ["isolate host"], "available_actions": ["quarantine", "notify"],
        "evidence": {"path": "/tmp/x"}, "ai_verdict": {"label": "tp", "confidence": 0.88},
        "cve_ids": ["CVE-2024-1"], "kev": True, "exploit_available": False,
    })
    assert row["finding_id"] == 7
    assert row["validation_score_pct"] == 90
    assert row["remediation"] == "isolate host"
    assert row["actions_performed"] == "quarantine; notify"
    assert row["ai_verdict"] == "tp"
    assert row["ai_confidence_pct"] == 88
    assert row["kev"] == "Yes"
    assert row["exploit_available"] == "No"
    assert '"path": "/tmp/x"' in row["evidence"] or '"path":"/tmp/x"' in row["evidence"]
    for key, _ in INCIDENT_COLUMNS:
        assert key in row

def test_timeline_row_joins_incident_and_isoformats_epoch():
    row = timeline_row(
        {"source": "case", "actor": "alice", "action": "status_change",
         "from_status": "new", "to_status": "triaging", "note": "n", "created_at": 1700000000},
        {"id": 7, "finding_uid": "u7", "title": "T", "severity": "high", "terrain": "citadels"},
    )
    assert row["finding_id"] == 7
    assert row["actor"] == "alice"
    assert row["event_time"].startswith("2023-11-14T")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd manager && python -m pytest tests/unit/test_reports_export.py -v`
Expected: FAIL — `manager.api.reports` does not exist.

- [ ] **Step 3: Implement the pure helpers**

Create `manager/manager/api/reports.py` (helpers only for this task; router added in B2):
```python
"""reports.py — server-side report assembly + streaming export endpoint.

Mirrors the client-side column set in the dashboard's reportData.ts so the
Phase A (browser) and Phase B (server) exports produce the identical workbook.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

INCIDENT_COLUMNS: list[tuple[str, str]] = [
    ("finding_id", "Finding ID"), ("finding_uid", "Finding UID"), ("external_id", "External ID"),
    ("asset_agent_id", "Agent ID"), ("asset_hostname", "Hostname"),
    ("first_detected_at", "First Detected"), ("last_detected_at", "Last Detected"),
    ("incident_title", "Incident"), ("category", "Category"), ("terrain", "Terrain"),
    ("severity", "Severity"), ("status", "Status"), ("description", "Description"),
    ("business_impact", "Business Impact"), ("confidence_pct", "Confidence %"),
    ("validation_score_pct", "Validation Score %"), ("source", "Source"), ("rule_id", "Rule ID"),
    ("mitre_tactic", "MITRE Tactic"), ("mitre_technique", "MITRE Technique"),
    ("cve_ids", "CVE IDs"), ("cvss_score", "CVSS"), ("kev", "KEV"),
    ("exploit_available", "Exploit Available"), ("ai_verdict", "AI Verdict"),
    ("ai_confidence_pct", "AI Confidence %"), ("ai_reasoning", "AI Reasoning"),
    ("remediation", "Remediation"), ("actions_performed", "Actions"),
    ("scan_count", "Scan Count"), ("evidence", "Evidence (JSON)"),
]
TIMELINE_COLUMNS = [
    ("finding_id", "Finding ID"), ("finding_uid", "Finding UID"), ("incident_title", "Incident"),
    ("severity", "Severity"), ("terrain", "Terrain"), ("event_time", "Event Time"),
    ("elapsed", "Elapsed"), ("source", "Source"), ("actor", "Actor"), ("action", "Action"),
    ("from_status", "From Status"), ("to_status", "To Status"), ("note", "Note"),
    ("changed_fields", "Changed Fields"), ("metadata", "Metadata"),
]
TELEMETRY_COLUMNS = [
    ("timestamp", "Timestamp"), ("agent_id", "Agent ID"), ("agent_name", "Agent Name"),
    ("section", "Section"), ("record_count", "Records"), ("ingest_lag_s", "Ingest Lag (s)"),
    ("data", "Data (JSON)"),
]
SUMMARY_COLUMNS = [("field", "Field"), ("value", "Value")]


def _iso(v) -> str:
    if v in (None, ""):
        return ""
    try:
        n = float(v)
        if n > 1_000_000_000:
            return datetime.fromtimestamp(n, tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        pass
    return str(v)


def _yesno(b) -> str:
    return "Yes" if b else "No"


def _join(v, sep="; ") -> str:
    if isinstance(v, list):
        return sep.join(json.dumps(x) if isinstance(x, (dict, list)) else str(x) for x in v)
    return "" if v is None else str(v)


def incident_row(f: dict) -> dict:
    ai = f.get("ai_verdict") or {}
    ps = f.get("precision_score")
    conf = ai.get("confidence")
    return {
        "finding_id": f.get("id"),
        "finding_uid": f.get("finding_uid", ""),
        "external_id": f.get("external_id", ""),
        "asset_agent_id": f.get("agent_id", ""),
        "asset_hostname": f.get("agent_hostname", ""),
        "first_detected_at": _iso(f.get("first_detected_at")),
        "last_detected_at": _iso(f.get("last_detected_at")),
        "incident_title": f.get("title", ""),
        "category": f.get("category", ""),
        "terrain": f.get("terrain", ""),
        "severity": f.get("severity", ""),
        "status": f.get("status", ""),
        "description": f.get("description", ""),
        "business_impact": f.get("impact", ""),
        "confidence_pct": f.get("confidence_pct", ""),
        "validation_score_pct": round(ps * 100) if isinstance(ps, (int, float)) else "",
        "source": f.get("source", ""),
        "rule_id": f.get("rule_id", ""),
        "mitre_tactic": f.get("mitre_tactic", ""),
        "mitre_technique": f.get("mitre_technique", ""),
        "cve_ids": _join(f.get("cve_ids"), ", "),
        "cvss_score": f.get("cvss_score", ""),
        "kev": _yesno(f.get("kev")),
        "exploit_available": _yesno(f.get("exploit_available")),
        "ai_verdict": ai.get("label", ""),
        "ai_confidence_pct": round(conf * 100) if isinstance(conf, (int, float)) else "",
        "ai_reasoning": ai.get("reasoning", ""),
        "remediation": _join(f.get("action_plan")),
        "actions_performed": _join(f.get("available_actions")),
        "scan_count": f.get("scan_count", ""),
        "evidence": json.dumps(f.get("evidence")) if f.get("evidence") else "",
    }


def timeline_row(ev: dict, f: dict) -> dict:
    return {
        "finding_id": f.get("id"),
        "finding_uid": f.get("finding_uid") or ev.get("finding_uid", ""),
        "incident_title": f.get("title", ""),
        "severity": f.get("severity", ""),
        "terrain": f.get("terrain", ""),
        "event_time": _iso(ev.get("created_at")),
        "elapsed": ev.get("elapsed", ""),
        "source": ev.get("source", ""),
        "actor": ev.get("actor", ""),
        "action": ev.get("action", ""),
        "from_status": ev.get("from_status", ""),
        "to_status": ev.get("to_status", ""),
        "note": ev.get("note", ""),
        "changed_fields": json.dumps(ev.get("changed_fields")) if ev.get("changed_fields") else "",
        "metadata": json.dumps(ev.get("metadata")) if ev.get("metadata") else "",
    }


def summary_rows(incidents, timeline_count, deep, mesh, window, filters):
    def by(key):
        acc: dict[str, int] = {}
        for f in incidents:
            k = str(f.get(key) or "unknown")
            acc[k] = acc.get(k, 0) + 1
        return ", ".join(f"{k}: {v}" for k, v in acc.items())
    return [
        {"field": "Generated At", "value": datetime.now(timezone.utc).isoformat()},
        {"field": "Platform", "value": "AttackLens"},
        {"field": "Time Window", "value": window},
        {"field": "Filters Applied", "value": filters or "none"},
        {"field": "Total Incidents", "value": len(incidents)},
        {"field": "Incidents by Severity", "value": by("severity")},
        {"field": "Incidents by Terrain", "value": by("terrain")},
        {"field": "Incidents by Status", "value": by("status")},
        {"field": "Total Timeline Events", "value": timeline_count},
        {"field": "Deep Analysis Rows", "value": deep},
        {"field": "DeepMesh Rows", "value": mesh},
    ]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd manager && python -m pytest tests/unit/test_reports_export.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add manager/manager/api/reports.py manager/tests/unit/test_reports_export.py
git commit -m "feat(reports): backend row-assembly helpers (parity with front-end columns)"
```

---

### Task B2: `/api/v1/reports/export` streaming endpoint

**Files:**
- Modify: `manager/manager/api/reports.py` (add `make_reports_router`)
- Modify: `manager/manager/server.py` (register the router)
- Modify: `manager/pyproject.toml` (add `xlsxwriter`)
- Test: `manager/tests/unit/test_reports_endpoint.py`

**Interfaces:**
- Consumes: `incident_row`, `timeline_row`, `summary_rows`, the `*_COLUMNS` from B1; the intel DB (`get_finding_timeline`, findings query) and raw store used by the existing detection/raw routers.
- Produces: `make_reports_router(intel_db, db) -> APIRouter` mounting `GET /api/v1/reports/export`.

- [ ] **Step 1: Add xlsxwriter**

In `manager/pyproject.toml` dependencies add `"xlsxwriter>=3.2"`. Run `cd manager && pip install xlsxwriter` (or `uv pip install xlsxwriter`) in the dev env.

- [ ] **Step 2: Write the failing endpoint test**

Create `manager/tests/unit/test_reports_endpoint.py`:
```python
import io, zipfile
from fastapi import FastAPI
from fastapi.testclient import TestClient
from manager.api.reports import make_reports_router

class FakeIntel:
    async def query_findings(self, **_):  # matches the shape used by detection/all
        return [{"id": 1, "title": "T", "severity": "high", "terrain": "citadels",
                 "evidence": {"a": 1}, "action_plan": ["fix"], "ai_verdict": {}}]
    async def get_finding_timeline(self, fid):
        return [{"source": "case", "actor": "sys", "action": "opened", "created_at": 1700000000}]

def _app():
    app = FastAPI()
    app.include_router(make_reports_router(FakeIntel(), db=None), prefix="/api/v1")
    return app

def test_csv_export_returns_incident_header_and_row():
    c = TestClient(_app())
    r = c.get("/api/v1/reports/export?type=incident&format=csv")
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.content))
    incidents = z.read([n for n in z.namelist() if "Incidents" in n][0]).decode()
    assert "Finding ID" in incidents and "\r\n1," in incidents
```
(If the router is session-guarded by a dependency that the bare `TestClient` can't satisfy, inject a test override for that dependency in `_app()` — mirror how `manager/tests/unit/test_api_auth_coverage.py` builds its client.)

- [ ] **Step 3: Run test to verify it fails**

Run: `cd manager && python -m pytest tests/unit/test_reports_endpoint.py -v`
Expected: FAIL — `make_reports_router` not defined.

- [ ] **Step 4: Implement the router**

Append to `manager/manager/api/reports.py`:
```python
import csv as _csv
from io import BytesIO, StringIO
from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse


def _rows_for(columns, rows):
    keys = [k for k, _ in columns]
    yield [h for _, h in columns]
    for r in rows:
        yield [r.get(k, "") for k in keys]


def _csv_bytes(columns, rows) -> bytes:
    buf = StringIO()
    w = _csv.writer(buf)
    for line in _rows_for(columns, rows):
        w.writerow(line)
    return buf.getvalue().encode("utf-8")


def _xlsx_bytes(sheets) -> bytes:
    import xlsxwriter
    bio = BytesIO()
    wb = xlsxwriter.Workbook(bio, {"in_memory": True})
    fills = {"critical": wb.add_format({"bg_color": "#FEE2E2"}),
             "high": wb.add_format({"bg_color": "#FEF3C7"}),
             "medium": wb.add_format({"bg_color": "#DBEAFE"})}
    header = wb.add_format({"bold": True})
    for name, columns, rows, severity_key in sheets:
        ws = wb.add_worksheet(name[:31])
        ws.freeze_panes(1, 0)
        for c, (_, h) in enumerate(columns):
            ws.write(0, c, h, header)
        for ridx, r in enumerate(rows, start=1):
            fmt = fills.get(str(r.get(severity_key, "")).lower()) if severity_key else None
            for c, (k, _) in enumerate(columns):
                v = r.get(k, "")
                ws.write(ridx, c, v if isinstance(v, (int, float, str)) else str(v), fmt)
    wb.close()
    return bio.getvalue()


def make_reports_router(intel_db, db=None) -> APIRouter:
    router = APIRouter()

    async def _gather_incidents():
        findings = await intel_db.query_findings()  # match the args detection/all uses
        incidents = [incident_row(f) for f in findings]
        tl_rows = []
        for f in findings:
            for ev in await intel_db.get_finding_timeline(f.get("id")):
                tl_rows.append(timeline_row(ev, f))
        return findings, incidents, tl_rows

    @router.get("/reports/export")
    async def export(type: str = Query("all"), format: str = Query("xlsx"),
                     window: str = Query("7d")):
        findings, incidents, tl_rows = await _gather_incidents()
        deep_rows: list[dict] = []   # wire to the raw store like the /raw/query route
        mesh_rows: list[dict] = []
        summary = summary_rows(findings, len(tl_rows), len(deep_rows), len(mesh_rows), window, "none")

        catalog = {
            "Summary": (SUMMARY_COLUMNS, summary, None),
            "Incidents": (INCIDENT_COLUMNS, incidents, "severity"),
            "Timeline": (TIMELINE_COLUMNS, tl_rows, None),
            "Deep Analysis": (TELEMETRY_COLUMNS, deep_rows, None),
            "DeepMesh (AI Security)": (TELEMETRY_COLUMNS, mesh_rows, None),
        }
        if type == "incident":
            names = ["Incidents", "Timeline"]
        elif type == "telemetry":
            names = ["Deep Analysis", "DeepMesh (AI Security)"]
        else:
            names = list(catalog.keys())

        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if format == "csv":
            zbio = BytesIO()
            import zipfile
            with zipfile.ZipFile(zbio, "w", zipfile.ZIP_DEFLATED) as zf:
                for n in names:
                    cols, rows, _ = catalog[n]
                    zf.writestr(f"{n.replace(' ', '_')}.csv", _csv_bytes(cols, rows))
            data, mime, ext = zbio.getvalue(), "application/zip", "zip"
        else:
            sheets = [(n, *catalog[n]) for n in names]
            data, mime, ext = _xlsx_bytes(sheets), \
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"

        return StreamingResponse(
            iter([data]), media_type=mime,
            headers={"Content-Disposition": f'attachment; filename="attacklens-report-{ts}.{ext}"'},
        )

    return router
```

- [ ] **Step 5: Register the router (guarded + tenant-scoped)**

In `manager/manager/server.py`, where the other routers are included, add (match the exact `include_router`/prefix/`dependencies=[Depends(require_session)]` pattern used by `findings`/`detection`):
```python
from manager.api.reports import make_reports_router
app.include_router(make_reports_router(intel_db, db), prefix="/api/v1",
                   dependencies=[Depends(require_session)])
```

- [ ] **Step 6: Run tests**

Run: `cd manager && python -m pytest tests/unit/test_reports_export.py tests/unit/test_reports_endpoint.py -v`
Expected: PASS. Then wire `query_findings`/raw-store calls to the real intel_db/raw methods the detection & raw routers use, and re-run.

- [ ] **Step 7: Commit**

```bash
git add manager/manager/api/reports.py manager/manager/server.py manager/pyproject.toml manager/tests/unit/test_reports_endpoint.py
git commit -m "feat(reports): streaming /api/v1/reports/export (xlsx + csv-zip), session-guarded"
```

---

### Task B3: Front-end routes large exports to the backend

**Files:**
- Modify: `src/app/lib/reportData.ts` (add `serverExport`)
- Modify: `src/app/pages/Reports.tsx` (use it above a row threshold)

- [ ] **Step 1: Add `serverExport` to `reportData.ts`**
```ts
export function serverExport(type: "all" | "incident" | "telemetry", format: "xlsx" | "csv", params: URLSearchParams): void {
  const u = new URL("/api/v1/reports/export", window.location.origin);
  u.searchParams.set("type", type);
  u.searchParams.set("format", format);
  params.forEach((v, k) => u.searchParams.set(k, v));
  window.location.href = u.toString(); // browser downloads the streamed attachment
}
```

- [ ] **Step 2: Use it in `Reports.tsx`**

Before the client-side gather, fetch `/api/v1/detection/all?...&limit=1` (or the count endpoint) to learn the total; if it exceeds `5000`, call `serverExport(...)` instead of building client-side. Keep the client path for smaller exports.

- [ ] **Step 3: Rebuild + commit**
```bash
cd "manager/dashboard/templates/Build Smart AttackLens Platform" && npm run build
cd - && git add "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/lib/reportData.ts" "manager/dashboard/templates/Build Smart AttackLens Platform/src/app/pages/Reports.tsx" manager/dashboard/static
git commit -m "feat(reports): route large exports to backend endpoint"
```

---

## Self-Review

**Spec coverage:** Summary sheet → A3/B2 `buildSummary`/`summary_rows`; Incidents (+evidence) → A2/B1 `mapIncident`/`incident_row`; Timeline → A2/B1 `mapTimelineEvent`/`timeline_row` + A3 `fetchTimelines` / B2 per-finding loop; Deep Analysis + DeepMesh → A3 `gatherTelemetry` / B2 telemetry rows; client-side (Phase A) → A1–A4; backend endpoint (Phase B) → B1–B3; error handling → A3 try/catch banner; tests → each task. All spec §3–§7 items map to a task.

**Placeholder scan:** Code shown for every code step. The two intentionally-deferred integration points (`fetchAllPages` pagination shape; `_gather_incidents` real intel_db/raw calls) each have an explicit verify step (A2 Step 5, B2 Step 6) that names the sibling file to copy — not a "TODO".

**Type consistency:** Column keys are identical across `reportData.ts` (`INCIDENT_COLS` etc.) and `reports.py` (`INCIDENT_COLUMNS` etc.); `mapIncident`/`incident_row`, `mapTimelineEvent`/`timeline_row` return the same keys; `Sheet`/`Col` names consistent across A1→A3; `make_reports_router(intel_db, db)` signature matches B1→B2→server.py.
