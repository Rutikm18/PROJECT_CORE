/**
 * Server-render smoke test for the pages added to Attack Terrain and Settings.
 *
 * There is no DOM environment in this project, but `react-dom/server` needs
 * none — and the initial render is where the interesting failures live: a bad
 * hook order, a destructure of something undefined, a `.map` over a field the
 * API has not returned yet. Type-checking cannot catch any of those.
 *
 * Effects do not run under SSR, so each page renders its zero-data state. That
 * is deliberate: an empty tenant is the first thing a real operator sees, and
 * it is the state most likely to crash on an unguarded array access.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import IdentityTerrain from "./IdentityTerrain";
import PostureTerrain from "./PostureTerrain";
import ValidationPipelinePanel from "./settings/ValidationPipelinePanel";

beforeEach(() => {
  // Nothing should reach the network during an initial render; if a page ever
  // starts fetching in render rather than in an effect, this makes it loud.
  vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("no network in render"))));
});

describe("Identity terrain page", () => {
  it("renders its zero-data state without throwing", () => {
    const html = renderToStaticMarkup(<IdentityTerrain />);
    expect(html).toContain("Identity — Accounts &amp; Credentials");
    expect(html).toContain("Identity Incidents");
  });

  it("shows every KPI tile", () => {
    const html = renderToStaticMarkup(<IdentityTerrain />);
    for (const tile of [
      "Identity Incidents", "Critical / High", "Root-Equivalent",
      "Service Shells", "Privilege Changes",
    ]) {
      expect(html, tile).toContain(tile);
    }
  });

  it("hides the root-equivalent alert strip when there are no findings", () => {
    const html = renderToStaticMarkup(<IdentityTerrain />);
    // Matched on strip-only wording: "root-equivalent accounts" also appears
    // in the page subtitle, which is always rendered.
    expect(html).not.toContain("classic backdoor admin");
    expect(html).toContain("root-equivalent accounts");   // subtitle still there
  });
});

describe("Posture terrain page", () => {
  it("renders its zero-data state without throwing", () => {
    const html = renderToStaticMarkup(<PostureTerrain />);
    expect(html).toContain("Posture — Security Controls");
    expect(html).toContain("Posture Incidents");
  });

  it("shows every KPI tile", () => {
    const html = renderToStaticMarkup(<PostureTerrain />);
    for (const tile of [
      "Posture Incidents", "Critical / High", "Controls Disabled",
      "Compliance Failures", "Hardware Integrity",
    ]) {
      expect(html, tile).toContain(tile);
    }
  });

  it("does not claim SIP is off when there are no findings", () => {
    const html = renderToStaticMarkup(<PostureTerrain />);
    expect(html).not.toContain("System Integrity Protection is disabled");
  });
});

describe("Validation pipeline panel", () => {
  it("renders its loading state without throwing", () => {
    const html = renderToStaticMarkup(<ValidationPipelinePanel />);
    expect(html).toContain("Loading validation pipeline");
  });
});
