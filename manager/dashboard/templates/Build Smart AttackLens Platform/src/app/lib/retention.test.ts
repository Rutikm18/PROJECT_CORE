/**
 * Retention panel logic — the parts that made "change the dropdown and nothing
 * happens" possible.
 *
 * Two bugs are pinned here:
 *   1. The <select> is fully controlled by the server config, so it did not
 *      move until PUT+GET completed. optimisticRetentionConfig lets the UI
 *      reflect the choice on click, and roll back if the write fails.
 *   2. The 60s stats poll and the save-reload both wrote config with no
 *      ordering, so a poll issued *before* a save could land *after* it and
 *      revert the dropdown. isStaleResponse discards superseded responses.
 */
import { describe, it, expect } from "vitest";

import {
  isSlowFetchPeriod,
  optimisticRetentionConfig,
  isStaleResponse,
  RETENTION_PERIOD_CODES,
} from "./retention";

const base = {
  period_months: 0,
  period_days: 1,
  action: "delete" as const,
  slow_fetch_warning: false,
  auto_resolve_stale_days: 2,
  available_periods: [...RETENTION_PERIOD_CODES],
  available_actions: ["delete", "archive"],
};

describe("isSlowFetchPeriod", () => {
  it("flags only the 1- and 2-year windows", () => {
    expect(isSlowFetchPeriod(12)).toBe(true);
    expect(isSlowFetchPeriod(24)).toBe(true);
  });

  it("leaves every shorter window unflagged", () => {
    for (const code of [0, 7, 15, 1, 3, 6]) {
      expect(isSlowFetchPeriod(code)).toBe(false);
    }
  });
});

describe("optimisticRetentionConfig", () => {
  it("moves the period immediately so the select reflects the click", () => {
    const next = optimisticRetentionConfig(base, { periodMonths: 15, action: "delete" });
    expect(next.period_months).toBe(15);
  });

  it("recomputes the slow-fetch warning with the new period", () => {
    expect(optimisticRetentionConfig(base, { periodMonths: 24, action: "delete" })
      .slow_fetch_warning).toBe(true);
    const slow = { ...base, period_months: 24, slow_fetch_warning: true };
    expect(optimisticRetentionConfig(slow, { periodMonths: 7, action: "delete" })
      .slow_fetch_warning).toBe(false);
  });

  it("carries the action through", () => {
    expect(optimisticRetentionConfig(base, { periodMonths: 0, action: "archive" })
      .action).toBe("archive");
  });

  it("keeps auto-resolve untouched when the caller omits it", () => {
    const next = optimisticRetentionConfig(base, { periodMonths: 3, action: "delete" });
    expect(next.auto_resolve_stale_days).toBe(2);
  });

  it("updates auto-resolve when the caller supplies it", () => {
    const next = optimisticRetentionConfig(base, {
      periodMonths: 3, action: "delete", autoResolveDays: 14,
    });
    expect(next.auto_resolve_stale_days).toBe(14);
  });

  it("does not mutate the config it was given, so rollback keeps the old value", () => {
    const snapshot = { ...base };
    optimisticRetentionConfig(base, { periodMonths: 24, action: "archive", autoResolveDays: 7 });
    expect(base).toEqual(snapshot);
  });

  it("returns null when there is no config yet", () => {
    expect(optimisticRetentionConfig(null, { periodMonths: 7, action: "delete" })).toBeNull();
  });
});

describe("isStaleResponse", () => {
  it("accepts the response of the newest request", () => {
    expect(isStaleResponse(5, 5)).toBe(false);
  });

  it("discards a poll that was superseded by a later save", () => {
    // poll issued at seq 4, save bumped the counter to 5 before the poll
    // resolved — applying it would revert the user's change.
    expect(isStaleResponse(4, 5)).toBe(true);
  });

  it("discards every older response, not just the immediately previous one", () => {
    expect(isStaleResponse(1, 9)).toBe(true);
  });
});

describe("RETENTION_PERIOD_CODES", () => {
  it("matches the backend's order: day presets first, then month presets", () => {
    expect([...RETENTION_PERIOD_CODES]).toEqual([0, 7, 15, 1, 3, 6, 12, 24]);
  });
});
