/**
 * Server-render smoke test for the Reports page. No DOM in this project, so we
 * render the zero-data state with react-dom/server (effects don't run under
 * SSR, and this page fetches only on button click — so nothing hits the
 * network during render). Catches bad hook order / undefined destructures.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import Reports from "./Reports";

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new Error("no network in render"))));
});

describe("Reports page", () => {
  it("renders without throwing and shows the three tabs", () => {
    const html = renderToStaticMarkup(<Reports />);
    expect(html).toContain("Telemetry Export");
    expect(html).toContain("Incident Report");
    expect(html).toContain("Full Report");
  });

  it("shows both export buttons", () => {
    const html = renderToStaticMarkup(<Reports />);
    expect(html).toContain("Download Excel");
    expect(html).toContain("Download CSV");
  });
});
