import { describe, it, expect } from "vitest";
import {
  KIND_PHASE, countFailures, formatConfigValue, phaseFor,
} from "./ValidationPipelinePanel";

describe("stage phase grouping", () => {
  it("assigns a phase to every stage kind the backend emits", () => {
    // pipeline_inventory.Stage.kind values.
    const kinds = [
      "schema", "allowlist", "gate", "enrichment", "scoring",
      "model", "policy", "threshold", "ledger", "orchestration",
    ];
    for (const kind of kinds) {
      expect(KIND_PHASE[kind], `kind ${kind}`).toBeDefined();
    }
  });

  it("falls back to Other for an unrecognised kind rather than rendering blank", () => {
    expect(phaseFor("something_new")).toBe("Other");
  });
});

describe("config value formatting", () => {
  it("renders booleans as words, not as 1/0", () => {
    expect(formatConfigValue(true)).toBe("true");
    expect(formatConfigValue(false)).toBe("false");
  });

  it("renders an unset value as an em dash", () => {
    expect(formatConfigValue(null)).toBe("—");
    expect(formatConfigValue(undefined)).toBe("—");
  });

  it("never renders [object Object] for a nested config value", () => {
    // correlation_window_sec resolves to a dict of three windows.
    const rendered = formatConfigValue({ default: 3600, persistence: 86400 });
    expect(rendered).not.toContain("object Object");
    expect(rendered).toContain("3600");
  });

  it("keeps zero visible instead of treating it as absent", () => {
    expect(formatConfigValue(0)).toBe("0");
  });
});

describe("failure badge count", () => {
  it("sums error classes and failed recompute jobs", () => {
    expect(countFailures({
      errors: { llm_timeout: 2, schema_violation: 1 },
      recompute_jobs: { running: 5, error: 3 },
      alerts: [],
    })).toBe(6);
  });

  it("ignores running and pending jobs, which are not failures", () => {
    expect(countFailures({
      errors: {},
      recompute_jobs: { pending: 4, running: 2 },
      alerts: [],
    })).toBe(0);
  });

  it("is zero when nothing is broken or the report is missing", () => {
    expect(countFailures({ errors: {}, recompute_jobs: {}, alerts: [] })).toBe(0);
    expect(countFailures(undefined)).toBe(0);
  });
});
