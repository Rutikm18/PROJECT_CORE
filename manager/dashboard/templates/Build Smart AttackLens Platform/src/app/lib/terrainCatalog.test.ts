import { describe, expect, it } from "vitest";
import { parseTerrainCatalog } from "./terrainCatalog";

describe("terrain catalog", () => {
  it("accepts server-owned labels, routes, colors, and categories", () => {
    expect(parseTerrainCatalog({ terrains: [{
      id: "mesh",
      label: "Mesh",
      validation_label: "Mesh validation",
      description: "Developer tooling",
      color: "#06b6d4",
      route: "/terrain/mesh",
      categories: ["developer_security"],
    }] })).toEqual([expect.objectContaining({
      id: "mesh",
      route: "/terrain/mesh",
      categories: ["developer_security"],
    })]);
  });

  it("rejects malformed entries", () => {
    expect(parseTerrainCatalog({ terrains: [null, { label: "Missing id" }] })).toEqual([]);
  });
});
