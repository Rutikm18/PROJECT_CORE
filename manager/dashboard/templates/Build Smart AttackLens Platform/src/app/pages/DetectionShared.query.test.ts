import { describe, expect, it } from "vitest";
import {
  DEFAULT_TERRAIN_FILTERS,
  buildTerrainDataUrl,
  parseDetectionPayload,
} from "./DetectionShared";

describe("terrain finding query", () => {
  it("serializes every standard filter for backend evaluation", () => {
    const url = new URL(buildTerrainDataUrl(
      "/api/v1/detection/all?validated_only=true",
      {
        ...DEFAULT_TERRAIN_FILTERS,
        agentId: "agent-a",
        severity: "high",
        terrainFilter: "mesh",
        statusFilter: "new",
        categoryFilter: "developer_security",
        search: "MCP server",
        mitreFilter: "Initial Access",
        kevOnly: true,
        exploitOnly: true,
        sortBy: "epss",
        sortDir: "asc",
      },
      [{ id: "1", field: "title", op: "contains", value: "MCP" }],
      { limit: 25, offset: 50 },
    ), "https://attacklens.test");

    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      validated_only: "true",
      agent_id: "agent-a",
      severity: "high",
      terrain_id: "mesh",
      status: "new",
      category: "developer_security",
      search: "MCP server",
      mitre: "Initial Access",
      kev_only: "true",
      exploit_only: "true",
      sort_by: "epss_score",
      sort_dir: "asc",
      limit: "25",
      offset: "50",
    });
    expect(JSON.parse(url.searchParams.get("advanced") || "[]")).toEqual([
      { field: "title", op: "contains", value: "MCP" },
    ]);
  });

  it("uses the indexed ID predicate for finding IDs", () => {
    const url = new URL(buildTerrainDataUrl("/api/v1/detection/all", {
      ...DEFAULT_TERRAIN_FILTERS,
      search: "AL-F-00000123",
    }), "https://attacklens.test");

    expect(url.searchParams.get("id_search")).toBe("AL-F-00000123");
    expect(url.searchParams.has("search")).toBe(false);
  });

  it("keeps the server total separate from the current page", () => {
    const parsed = parseDetectionPayload({
      findings: [{ id: 1 }, { id: 2 }],
      total: 1_250,
      stats: { total: 1_250, critical: 12, high: 100, kev: 5 },
    });

    expect(parsed.findings).toHaveLength(2);
    expect(parsed.total).toBe(1_250);
    expect(parsed.stats).toEqual({ total: 1_250, critical: 12, high: 100, kev: 5 });
  });
});
