import { describe, expect, it } from "vitest";
import { VALIDATED_NEW_FINDINGS_URL } from "./Sidebar";

describe("Validated Findings sidebar badge", () => {
  it("counts only new findings in the validated projection", () => {
    const url = new URL(VALIDATED_NEW_FINDINGS_URL, "https://attacklens.test");
    expect(url.pathname).toBe("/api/v1/detection/all");
    expect(url.searchParams.get("status")).toBe("new");
    expect(url.searchParams.get("view")).toBe("active");
    expect(url.searchParams.get("validated_only")).toBe("true");
  });
});
