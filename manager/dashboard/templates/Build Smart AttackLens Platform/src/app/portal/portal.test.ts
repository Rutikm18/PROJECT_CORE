import { describe, it, expect } from "vitest";
import { PORTAL_LOGIN_PATH, redirectForStatus } from "./portalClient";
import { visibleGroups } from "./PortalSidebar";
import { orderedSeverities, severityTone, SEVERITY_ORDER } from "./PortalPages";

/**
 * The portal is a separate principal, so the two things worth pinning on the
 * client are: a failed portal request never sends a customer to the operator
 * login, and navigation is built from the server's capability map rather than
 * anything the browser decides for itself.
 */

describe("auth failure routing", () => {
  it("sends an unauthenticated customer to the portal login", () => {
    expect(redirectForStatus(401)).toBe(PORTAL_LOGIN_PATH);
  });

  it("also redirects on 403 — a suspended org or an operator token", () => {
    // Both mean "you are not a valid customer here", and both should land on
    // the portal login rather than leaving the user on a broken page.
    expect(redirectForStatus(403)).toBe(PORTAL_LOGIN_PATH);
  });

  it("never sends a customer to the operator login", () => {
    for (const status of [401, 403]) {
      expect(redirectForStatus(status)).not.toBe("/login");
    }
  });

  it("leaves other failures where they are", () => {
    for (const status of [400, 404, 409, 429, 500, 503]) {
      expect(redirectForStatus(status), String(status)).toBeNull();
    }
  });
});

const paths = (caps: Record<string, boolean> | undefined) =>
  visibleGroups(caps).flatMap(g => g.items.map(i => i.to));

describe("navigation from server capabilities", () => {
  it("offers nothing beyond the dashboard before capabilities resolve", () => {
    // undefined = /auth/me has not answered. Least privilege, not most.
    expect(paths(undefined)).toEqual(["/portal"]);
  });

  it("mirrors the operator groups when the server allows it", () => {
    const shown = paths({
      view_findings: true, view_posture: true,
      view_reports: true, configure_dashboard: true,
    });
    expect(shown).toContain("/portal/findings");
    expect(shown).toContain("/portal/incidents");
    expect(shown).toContain("/portal/terrain/origin");
    expect(shown).toContain("/portal/terrain/posture");
    expect(shown).toContain("/portal/timeline");
    expect(shown).toContain("/portal/settings");
  });

  it("hides a capability the server explicitly withholds", () => {
    const shown = paths({ view_findings: false, configure_dashboard: true });
    expect(shown).toEqual(["/portal", "/portal/settings"]);
  });

  it("drops a group once every entry in it is withheld", () => {
    const groups = visibleGroups({ view_findings: false, configure_dashboard: true });
    expect(groups.map(g => g.label)).toEqual(["Operations", "Configuration"]);
  });

  it("never surfaces an operator route", () => {
    const shown = paths({
      view_findings: true, view_posture: true, view_reports: true,
      configure_dashboard: true,
      // Even if the server sent these, there is no nav entry for them.
      manage_users: true, manage_platform_settings: true, view_raw_telemetry: true,
    });
    for (const to of shown) expect(to.startsWith("/portal")).toBe(true);
  });

  it("shows the raw-telemetry pages once the server grants them", () => {
    // /api/v1/raw is scoped per tenant now, so Deep Analysis and DeepMesh read
    // the customer's OWN endpoint telemetry.
    const shown = paths({
      view_findings: true, view_posture: true, view_reports: true,
      configure_dashboard: true, view_raw_telemetry: true,
    });
    expect(shown).toContain("/portal/analysis");
    expect(shown).toContain("/portal/deepmesh");
  });

  it("hides them again when the capability is withheld", () => {
    const shown = paths({
      view_findings: true, view_posture: true, view_reports: true,
      configure_dashboard: true, view_raw_telemetry: false,
    });
    expect(shown).not.toContain("/portal/analysis");
    expect(shown).not.toContain("/portal/deepmesh");
  });

  it("never offers fleet-wide detection logic", () => {
    const shown = paths({
      view_findings: true, view_posture: true, view_reports: true,
      configure_dashboard: true, view_raw_telemetry: true,
    });
    // Custom Rules changes detection for every tenant — operator-only.
    expect(shown.some(p => p.includes("custom-rules"))).toBe(false);
  });
});

describe("severity presentation", () => {
  it("orders by urgency, not alphabetically", () => {
    const ordered = orderedSeverities({ low: 1, critical: 2, medium: 3, high: 4 });
    expect(ordered.map(([s]) => s)).toEqual(["critical", "high", "medium", "low"]);
  });

  it("drops empty buckets so the chart shows only what exists", () => {
    expect(orderedSeverities({ critical: 0, high: 2 })).toEqual([["high", 2]]);
    expect(orderedSeverities(undefined)).toEqual([]);
  });

  it("gives every severity a distinct tone", () => {
    const tones = new Set(SEVERITY_ORDER.map(severityTone));
    expect(tones.size).toBe(SEVERITY_ORDER.length);
  });

  it("falls back rather than rendering an unstyled chip", () => {
    expect(severityTone("nonsense")).toContain("gray");
  });
});
