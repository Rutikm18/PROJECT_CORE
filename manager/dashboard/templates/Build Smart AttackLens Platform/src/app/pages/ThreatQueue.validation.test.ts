import { describe, expect, it, vi } from "vitest";
import {
  VALIDATED_FINDINGS_URL,
  runValidationRecompute,
  validatedFindingsQuery,
} from "./ThreatQueue";

describe("Validated Findings projection", () => {
  it("reads the same canonical endpoint as All Incidents", () => {
    expect(VALIDATED_FINDINGS_URL).toBe("/api/v1/detection/all");
  });

  it.each(["active", "closed", "all"] as const)(
    "keeps validated_only enabled for the %s view",
    (view) => {
      const query = validatedFindingsQuery(view);
      expect(query.get("view")).toBe(view);
      expect(query.get("validated_only")).toBe("true");
    },
  );

  it("resumes bounded recompute batches until the durable job completes", async () => {
    const bodies = [
      { job_uid: "job-1", state: "running", scanned: 250, updated: 250, histogram: {} },
      { job_uid: "job-1", state: "completed", scanned: 300, updated: 300, histogram: {} },
    ];
    const request = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => bodies.shift(),
    } as Response));

    const result = await runValidationRecompute(request as typeof fetch);

    expect(result.state).toBe("completed");
    expect(request).toHaveBeenCalledTimes(2);
    expect(String(request.mock.calls[1][0])).toContain("/job-1/resume");
  });
});
