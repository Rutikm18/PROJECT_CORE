import { describe, expect, it } from "vitest";

import {
  buildCaseCreatePayload,
  buildLegacyCaseImport,
  countOpenCases,
  parseCaseList,
} from "./Incidents";


describe("Incidents case API contract", () => {
  it("parses the backend collection envelope", () => {
    const cases = parseCaseList({
      cases: [{ id: 7, external_id: "CASE-2026-000007", findings: [11], tags: ["mesh"] }],
    });

    expect(cases).toHaveLength(1);
    expect(cases[0].external_id).toBe("CASE-2026-000007");
    expect(cases[0].findings).toEqual([11]);
  });

  it("maps the UI draft to backend field names", () => {
    expect(buildCaseCreatePayload({
      title: "Mesh incident",
      description: "review",
      priority: "high",
      status: "open",
      assignee: "alice@example.com",
      tags: ["mesh"],
      findings: [11],
    })).toEqual({
      title: "Mesh incident",
      description: "review",
      priority: "high",
      status: "open",
      owner_user_id: "alice@example.com",
      tags: ["mesh"],
      finding_ids: [11],
    });
  });

  it("wraps only valid local cases for one-time import", () => {
    const payload = buildLegacyCaseImport([
      { id: "CASE-LOCAL", title: "Local case" },
      null,
      { id: "", title: "" },
    ]);

    expect(payload.cases).toEqual([{ id: "CASE-LOCAL", title: "Local case" }]);
  });

  it("counts open cases without throwing on malformed backend payloads", () => {
    expect(countOpenCases({ cases: [
      { id: 1, status: "open" },
      { id: 2, status: "in_progress" },
      { id: 3, status: "closed" },
    ] })).toBe(2);
    expect(countOpenCases({ error: "case service unavailable" })).toBe(0);
  });
});
