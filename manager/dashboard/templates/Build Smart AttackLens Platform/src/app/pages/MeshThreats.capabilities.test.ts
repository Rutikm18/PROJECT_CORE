import { describe, it, expect } from "vitest";
import { CAPABILITIES, capabilityForRule } from "./MeshThreats";

describe("mesh capability mapping", () => {
  it("maps each AL-DEV rule to exactly one capability", () => {
    const rules = ["AL-DEV-001","AL-DEV-002","AL-DEV-003","AL-DEV-004",
                   "AL-DEV-005","AL-DEV-006","AL-DEV-007","AL-DEV-008","AL-DEV-009"];
    for (const r of rules) {
      expect(capabilityForRule(r), `rule ${r}`).toBeDefined();
    }
  });

  it("groups both browser rules under one capability", () => {
    expect(capabilityForRule("AL-DEV-004")!.key).toBe("browser");
    expect(capabilityForRule("AL-DEV-005")!.key).toBe("browser");
  });

  it("returns undefined for unknown / missing rule", () => {
    expect(capabilityForRule("AL-DEV-999")).toBeUndefined();
    expect(capabilityForRule(undefined)).toBeUndefined();
  });

  it("every capability declares at least one rule and a search keyword", () => {
    for (const c of CAPABILITIES) {
      expect(c.rules.length).toBeGreaterThan(0);
      expect(c.search.length).toBeGreaterThan(0);
    }
  });
});
