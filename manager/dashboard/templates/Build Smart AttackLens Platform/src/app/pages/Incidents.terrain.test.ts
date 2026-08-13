import { describe, expect, it } from "vitest";
import {
  buildIncidentTerrainTabs, countIncidentsByTerrain,
  parseIncidentQuery, updateIncidentQuery,
} from "./Incidents";

describe("All Incidents terrain filters", () => {
  it("includes Mesh and counts it from canonical terrain_id", () => {
    const tabs = buildIncidentTerrainTabs([
      "origin", "vector", "citadels", "identity", "posture", "mesh",
    ].map((id) => ({
      id, label: id[0].toUpperCase() + id.slice(1), validation_label: id,
      description: "", color: "#000", route: `/terrain/${id}`, categories: [],
    })));
    expect(tabs.map((terrain) => terrain.key)).toEqual([
      "all", "origin", "vector", "citadels", "identity", "posture", "mesh",
    ]);

    expect(countIncidentsByTerrain([
      { terrain_id: "mesh" },
      { terrain: "mesh" },
      { terrain_id: "origin" },
    ])).toMatchObject({ mesh: 2, origin: 1 });
  });
});

describe("incident URL state", () => {
  it("round-trips filters without removing the shared time range", () => {
    const params = updateIncidentQuery(new URLSearchParams("window=6h"), {
      terrain: "mesh", status: "new", validated: true, view: "timeline",
    });

    expect(params.get("window")).toBe("6h");
    expect(parseIncidentQuery(params)).toEqual({
      terrain: "mesh", status: "new", validated: true, view: "timeline",
    });
  });
});
