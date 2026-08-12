import { describe, it, expect } from "vitest";
import { countPartialHosts } from "./MeshThreats";

describe("countPartialHosts", () => {
  it("counts rows whose summary.partial is true", () => {
    const rows = [
      { summary: { partial: true } },
      { summary: { partial: false } },
      { summary: null },
      { summary: { partial: true } },
    ];
    expect(countPartialHosts(rows)).toBe(2);
  });

  it("returns 0 for empty / undefined", () => {
    expect(countPartialHosts([])).toBe(0);
    expect(countPartialHosts(undefined)).toBe(0);
  });
});
