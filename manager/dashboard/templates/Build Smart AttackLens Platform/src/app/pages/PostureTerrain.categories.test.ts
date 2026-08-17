import { describe, it, expect } from "vitest";
import {
  POSTURE_CATEGORIES, POSTURE_CONTROL_KEYS,
  countPostureCategories, countDisabledControls, disabledControl,
} from "./PostureTerrain";

describe("posture category mapping", () => {
  it("covers every category terrain_catalog assigns to posture", () => {
    // terrain_catalog.py posture categories, minus the two ("posture", "sip")
    // that are aliases already folded into the Controls bucket.
    const backend = [
      "security", "posture", "sip", "firewall",
      "agent_health", "battery", "hardware", "compliance",
    ];
    const claimed = new Set(POSTURE_CATEGORIES.flatMap(c => c.categories));
    for (const category of backend) {
      expect(claimed.has(category), `category ${category}`).toBe(true);
    }
  });

  it("no category is claimed by two buckets", () => {
    const all = POSTURE_CATEGORIES.flatMap(c => c.categories);
    expect(new Set(all).size).toBe(all.length);
  });

  it("every bucket leads with the category the engine actually emits", () => {
    // The server-side filter takes categories[0], so the first entry has to be
    // the real emitted value, not an alias.
    const emitted = new Set([
      "security", "compliance", "hardware", "agent_health", "battery",
    ]);
    for (const bucket of POSTURE_CATEGORIES) {
      expect(emitted.has(bucket.categories[0]), bucket.key).toBe(true);
    }
  });

  it("counts findings per bucket, case-insensitively", () => {
    const counts = countPostureCategories([
      { category: "security" },
      { category: "SECURITY" },
      { category: "compliance" },
      { category: "not_a_posture_category" },
      {},
    ]);
    expect(counts.security).toBe(2);
    expect(counts.compliance).toBe(1);
    expect(counts.hardware).toBe(0);
  });
});

// Shapes taken from the two real emitters. The module one is what actually
// runs, because use_detection_modules defaults to true.
const mod = (controlKey: string, status = "disabled") => ({
  item_key: "posture_critical_disabled:adaf37adae1d11e6",
  evidence: { control_key: controlKey, status },
});
const inline = (key: string, value: unknown = "disabled") => ({
  item_key: `sec:${key}`,
  evidence: { [key]: value },
});

describe("disabled control extraction", () => {
  it("reads the routed detection module's control_key/status shape", () => {
    // Regression: matching only "sec:<key>" reported 0 controls off on a live
    // deployment that had a critical Secure Boot failure.
    expect(disabledControl(mod("sip_enabled"))).toBe("sip");
    expect(disabledControl(mod("secure_boot"))).toBe("secure_boot");
  });

  it("reads the inline analyzer's item_key/evidence shape", () => {
    expect(disabledControl(inline("sip"))).toBe("sip");
    expect(disabledControl(inline("filevault"))).toBe("filevault");
  });

  it("collapses module and inline spellings onto one control", () => {
    expect(disabledControl(mod("gatekeeper_enabled")))
      .toBe(disabledControl(inline("gatekeeper")));
  });

  it("accepts evidence stored as a JSON string", () => {
    expect(disabledControl({
      item_key: "x", evidence: JSON.stringify({ control_key: "sip_enabled", status: "disabled" }),
    })).toBe("sip");
  });

  it("treats an enabled control as not disabled", () => {
    expect(disabledControl(mod("sip_enabled", "enabled"))).toBe("");
    expect(disabledControl(inline("sip", true))).toBe("");
  });

  it("accepts bool false as well as the usual strings", () => {
    for (const v of ["off", "false", "no", "permissive", false]) {
      expect(disabledControl(inline("firewall", v)), String(v)).toBe("firewall");
    }
  });

  it("returns empty for a posture finding that is not a control failure", () => {
    expect(disabledControl({
      item_key: "agent_health:collector:processes",
      evidence: { collector: "processes", status: "degraded" },
    })).toBe("");
    expect(disabledControl({})).toBe("");
  });
});

describe("disabled control counting", () => {
  it("counts distinct controls across both emitters", () => {
    expect(countDisabledControls([
      mod("sip_enabled"), inline("filevault"),
      mod("gatekeeper_enabled"), inline("firewall"),
    ])).toBe(4);
  });

  it("does not double-count one control seen on two hosts or two emitters", () => {
    expect(countDisabledControls([mod("sip_enabled"), inline("sip")])).toBe(1);
  });

  it("excludes lockdown_mode, which is informational rather than a failure", () => {
    expect(countDisabledControls([inline("lockdown_mode", true), mod("sip_enabled")])).toBe(1);
  });

  it("ignores findings carrying no control evidence", () => {
    expect(countDisabledControls([{}, { item_key: "" }])).toBe(0);
  });

  it("covers the cross-platform controls, not just the four macOS ones", () => {
    expect([...POSTURE_CONTROL_KEYS]).toEqual(expect.arrayContaining([
      "sip", "gatekeeper", "filevault", "firewall",
      "secure_boot", "defender_realtime", "bitlocker", "selinux",
    ]));
  });
});
