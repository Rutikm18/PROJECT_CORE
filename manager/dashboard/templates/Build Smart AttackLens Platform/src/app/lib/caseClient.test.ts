import { describe, expect, it } from "vitest";
import { parseCase } from "./caseClient";

describe("caseClient", () => {
  it("parses the canonical backend case shape", () => {
    expect(parseCase({
      id: 7, external_id: "CASE-2026-000007", title: "Mesh", status: "in_progress",
      priority: "high", owner_user_id: "alice", due_at: 12, findings: [3], tags: ["mesh"],
      version: 2,
    })).toMatchObject({
      id: 7, status: "in_progress", priority: "high", owner_user_id: "alice",
      findings: [3], tags: ["mesh"], version: 2,
    });
  });

  it("rejects an object without a numeric backend id", () => {
    expect(parseCase({ title: "local preview" })).toBeNull();
  });
});
