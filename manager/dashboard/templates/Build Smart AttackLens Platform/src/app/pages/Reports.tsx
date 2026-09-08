import { useState } from "react";
import { FileText, Download, Loader2 } from "lucide-react";
import { toCSV, toXLSX, downloadText, type Sheet } from "../lib/exportUtils";
import {
  INCIDENT_COLS,
  TIMELINE_COLS,
  TELEMETRY_COLS,
  SUMMARY_COLS,
  mapIncident,
  mapTimelineEvent,
  mapTelemetry,
  buildSummary,
  fetchAllPages,
  fetchTimelines,
  serverExport,
} from "../lib/reportData";
import { rangeToParams, DEFAULT_RANGE } from "../lib/timeRange";

type Tab = "telemetry" | "incident" | "full";

// Above this many findings, hand the export to the streaming backend endpoint
// (Phase B) instead of assembling it in the browser.
const SERVER_THRESHOLD = 5000;

const TAB_LABEL: Record<Tab, string> = {
  telemetry: "Telemetry Export",
  incident: "Incident Report",
  full: "Full Report",
};

export default function Reports() {
  const [tab, setTab] = useState<Tab>("telemetry");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState("");
  const [error, setError] = useState("");

  async function agentNameMap(): Promise<(id: string) => string> {
    try {
      const res = await fetch("/api/v1/raw/agents");
      const list = res.ok ? await res.json() : [];
      const arr = Array.isArray(list) ? list : list.items || [];
      const m = new Map<string, string>(
        arr.map((a: any) => [a.agent_id ?? a.id, a.name ?? a.hostname ?? a.agent_id ?? a.id]),
      );
      return (id: string) => m.get(id) ?? id;
    } catch {
      return (id: string) => id;
    }
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
    const timelines = await fetchTimelines(
      findings.map((f) => f.id),
      { onProgress: (d, t) => setProgress(`Fetching timeline ${d}/${t}…`) },
    );
    const timelineRows = findings.flatMap((f) => (timelines.get(f.id) || []).map((ev) => mapTimelineEvent(ev, f)));
    return { findings, incidents, timelineRows };
  }

  function emit(sheets: Sheet[], fmt: "csv" | "xlsx", base: string) {
    if (fmt === "xlsx") {
      toXLSX(sheets, `${base}.xlsx`);
      return;
    }
    for (const s of sheets) {
      downloadText(toCSV(s.rows, s.cols), `${base}-${s.name.replace(/\W+/g, "_")}.csv`, "text/csv");
    }
  }

  async function run(kind: Tab, fmt: "csv" | "xlsx") {
    setBusy(true);
    setError("");
    setProgress("Fetching…");
    try {
      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      if (kind === "telemetry") {
        const deep = await gatherTelemetry();
        const mesh = await gatherTelemetry("developer_security");
        emit(
          [
            { name: "Deep Analysis", rows: deep, cols: TELEMETRY_COLS },
            { name: "DeepMesh (AI Security)", rows: mesh, cols: TELEMETRY_COLS },
          ],
          fmt,
          `attacklens-telemetry-${ts}`,
        );
      } else if (kind === "incident") {
        const { incidents, timelineRows } = await gatherIncidents();
        emit(
          [
            { name: "Incidents", rows: incidents, cols: INCIDENT_COLS, severityKey: "severity" },
            { name: "Timeline", rows: timelineRows, cols: TIMELINE_COLS },
          ],
          fmt,
          `attacklens-incidents-${ts}`,
        );
      } else {
        const deep = await gatherTelemetry();
        const mesh = await gatherTelemetry("developer_security");
        const { findings, incidents, timelineRows } = await gatherIncidents();
        const summary = buildSummary(findings, timelineRows.length, deep.length, mesh.length, "24h", "none");
        emit(
          [
            { name: "Summary", rows: summary, cols: SUMMARY_COLS },
            { name: "Incidents", rows: incidents, cols: INCIDENT_COLS, severityKey: "severity" },
            { name: "Timeline", rows: timelineRows, cols: TIMELINE_COLS },
            { name: "Deep Analysis", rows: deep, cols: TELEMETRY_COLS },
            { name: "DeepMesh (AI Security)", rows: mesh, cols: TELEMETRY_COLS },
          ],
          fmt,
          `attacklens-report-${ts}`,
        );
      }
    } catch (e: any) {
      setError(`Export failed: ${e?.message || e}. Try again.`);
    } finally {
      setBusy(false);
      setProgress("");
    }
  }

  // If the incident set is very large, let the backend stream it instead of
  // assembling in the browser (avoids the per-incident timeline N+1 at scale).
  async function maybeServerRoute(kind: Tab, fmt: "csv" | "xlsx"): Promise<boolean> {
    if (kind === "telemetry") return false;
    try {
      const res = await fetch(`/api/v1/detection/all?${rangeToParams(DEFAULT_RANGE).toString()}&limit=1`);
      const body = res.ok ? await res.json() : null;
      const total = body && !Array.isArray(body) ? Number(body.total || 0) : 0;
      if (total > SERVER_THRESHOLD) {
        serverExport(kind === "incident" ? "incident" : "all", fmt, rangeToParams(DEFAULT_RANGE));
        return true;
      }
    } catch {
      /* fall through to client-side */
    }
    return false;
  }

  async function onExport(fmt: "csv" | "xlsx") {
    if (await maybeServerRoute(tab, fmt)) return;
    await run(tab, fmt);
  }

  return (
    <div className="p-6">
      <div className="rounded-2xl shadow-card bg-white border-t-[3px] border-indigo-500 p-5 mb-4 flex items-center gap-3">
        <FileText className="text-indigo-600" />
        <div>
          <h1 className="text-lg font-semibold">Reports</h1>
          <p className="text-sm text-slate-500">
            Export Deep Analysis, DeepMesh (AI security), and full incident detail — evidence, scores, remediation,
            actions, and timeline history — as Excel or CSV.
          </p>
        </div>
      </div>

      <div className="flex gap-2 mb-4">
        {(["telemetry", "incident", "full"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-xl text-sm font-semibold ${
              tab === t ? "bg-white shadow-card text-slate-900" : "bg-slate-100 text-slate-600"
            }`}
          >
            {TAB_LABEL[t]}
          </button>
        ))}
      </div>

      {error && <div className="mb-3 rounded-xl bg-red-50 text-red-700 px-4 py-2 text-sm">{error}</div>}

      <div className="rounded-2xl bg-white shadow-card p-5">
        <p className="text-sm text-slate-600 mb-4">
          {tab === "telemetry"
            ? "Two sheets: Deep Analysis (all sections) and DeepMesh (developer/AI security)."
            : tab === "incident"
              ? "Two sheets: Incidents (with evidence + scores + remediation + actions) and Timeline (full history per incident)."
              : "One workbook with everything: Summary, Incidents, Timeline, Deep Analysis, and DeepMesh."}
        </p>
        <div className="flex gap-3 items-center">
          <button
            disabled={busy}
            onClick={() => onExport("xlsx")}
            className="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-60 text-white rounded-xl px-4 py-2 text-sm font-semibold"
          >
            {busy ? <Loader2 className="animate-spin size-4" /> : <Download className="size-4" />} Download Excel (.xlsx)
          </button>
          <button
            disabled={busy}
            onClick={() => onExport("csv")}
            className="inline-flex items-center gap-2 border border-slate-300 hover:bg-slate-50 disabled:opacity-60 rounded-xl px-4 py-2 text-sm font-semibold"
          >
            <Download className="size-4" /> Download CSV
          </button>
          {busy && <span className="text-sm text-slate-500">{progress}</span>}
        </div>
      </div>
    </div>
  );
}
