import { describe, it, expect } from "vitest";
import {
  mapIncident,
  mapTimelineEvent,
  mapTelemetry,
  buildSummary,
  INCIDENT_COLS,
  TIMELINE_COLS,
} from "./reportData";

describe("mapIncident", () => {
  it("flattens evidence + ai_verdict + score into the incident columns", () => {
    const row = mapIncident({
      id: 7,
      finding_uid: "u7",
      title: "Suspicious binary",
      terrain: "citadels",
      severity: "high",
      status: "new",
      precision_score: 0.9,
      confidence_pct: 82,
      action_plan: ["isolate host"],
      available_actions: ["quarantine", "notify"],
      evidence: { path: "/tmp/x", _source: "edr" },
      ai_verdict: { label: "tp", confidence: 0.88, reasoning: "matches TTP" },
      cve_ids: ["CVE-2024-1"],
      kev: true,
      exploit_available: false,
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
    for (const c of INCIDENT_COLS) expect(c.key in row).toBe(true);
  });
});

describe("mapTimelineEvent", () => {
  it("joins the incident context and converts epoch to ISO", () => {
    const row = mapTimelineEvent(
      {
        source: "case",
        actor: "alice",
        action: "status_change",
        from_status: "new",
        to_status: "triaging",
        note: "n",
        created_at: 1700000000,
      },
      { id: 7, finding_uid: "u7", title: "T", severity: "high", terrain: "citadels" },
    );
    expect(row.finding_id).toBe(7);
    expect(row.actor).toBe("alice");
    expect(row.event_time).toBe(new Date(1700000000 * 1000).toISOString());
    for (const c of TIMELINE_COLS) expect(c.key in row).toBe(true);
  });
});

describe("mapTelemetry", () => {
  it("computes ingest lag and resolves the agent name", () => {
    const row = mapTelemetry(
      { collected_at: 1700000000, received_at: 1700000005, agent_id: "a1", section: "processes", record_count: 12, data: { x: 1 } },
      (id) => (id === "a1" ? "host-1" : id),
    );
    expect(row.agent_name).toBe("host-1");
    expect(row.ingest_lag_s).toBe(5);
    expect(row.section).toBe("processes");
    expect(JSON.parse(String(row.data)).x).toBe(1);
  });
});

describe("buildSummary", () => {
  it("counts incidents by severity/terrain/status", () => {
    const rows = buildSummary(
      [
        { severity: "high", terrain: "citadels", status: "new" },
        { severity: "high", terrain: "mesh", status: "triaging" },
      ],
      3,
      100,
      20,
      "24h",
      "none",
    );
    const get = (f: string) => rows.find((r) => r.field === f)?.value;
    expect(get("Total Incidents")).toBe(2);
    expect(get("Incidents by Severity")).toBe("high: 2");
    expect(get("Total Timeline Events")).toBe(3);
    expect(get("Deep Analysis Rows")).toBe(100);
    expect(get("DeepMesh Rows")).toBe(20);
  });
});
