import { describe, it, expect } from "vitest";
import {
  IDENTITY_SIGNALS, countIdentitySignals, signalForSource,
} from "./IdentityTerrain";

describe("identity signal mapping", () => {
  it("maps every rule_id the routed detections/user_account module emits", () => {
    // This is the path that actually runs (use_detection_modules defaults to
    // true), and engine.py sets source = rule_id. Claiming only the inline
    // names left every chip reading zero on a real deployment.
    const moduleRules = [
      "uid_zero_clone", "service_with_shell", "privgroup_added",
      "new_account", "hidden_user", "home_changed", "shell_changed",
    ];
    for (const s of moduleRules) {
      expect(signalForSource(s), `module rule ${s}`).toBeDefined();
    }
  });

  it("still maps the inline analyzer and behavioural sources", () => {
    const sources = [
      "rule:uid0", "rule:svc_interactive_shell",
      "behavioral_change", "behavioral_new_entity", "behavioral_zscore",
    ];
    for (const s of sources) {
      expect(signalForSource(s), `source ${s}`).toBeDefined();
    }
  });

  it("puts both spellings of a control on the same chip", () => {
    expect(signalForSource("uid_zero_clone")!.key)
      .toBe(signalForSource("rule:uid0")!.key);
    expect(signalForSource("service_with_shell")!.key)
      .toBe(signalForSource("rule:svc_interactive_shell")!.key);
  });

  it("returns undefined for an unknown or missing source", () => {
    expect(signalForSource("rule:not_a_real_rule")).toBeUndefined();
    expect(signalForSource(undefined)).toBeUndefined();
  });

  it("every signal declares at least one source and a search keyword", () => {
    for (const s of IDENTITY_SIGNALS) {
      expect(s.sources.length).toBeGreaterThan(0);
      expect(s.search.length).toBeGreaterThan(0);
    }
  });

  it("no source is claimed by two signals", () => {
    const all = IDENTITY_SIGNALS.flatMap(s => s.sources);
    expect(new Set(all).size).toBe(all.length);
  });

  it("counts findings per signal and ignores unmapped sources", () => {
    const counts = countIdentitySignals([
      { source: "uid_zero_clone" },
      { source: "rule:uid0" },
      { source: "privgroup_added" },
      { source: "something_else" },
      {},
    ]);
    // Both emitters' names roll up into one chip.
    expect(counts.uid0).toBe(2);
    expect(counts.admin_grant).toBe(1);
    expect(counts.svc_shell).toBe(0);
  });

  it("returns a zeroed bucket for every signal even with no findings", () => {
    const counts = countIdentitySignals([]);
    expect(Object.keys(counts).sort()).toEqual(
      IDENTITY_SIGNALS.map(s => s.key).sort(),
    );
    expect(Object.values(counts).every(n => n === 0)).toBe(true);
  });
});
